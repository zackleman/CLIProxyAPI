package executor

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// Decoupled upstream websocket mode: Codex clients connected over plain HTTP/SSE
// still ride the persistent upstream websocket. Enabled by codex.upstream-websockets
// on top of the per-credential "websockets" attribute.
//
// Safety contract (see docs/plans/2026-09-13-fable-quota-routing-and-codex-ws.md):
//   - Connect/handshake failure: transparent single retry over HTTP, and the
//     credential's websocket path is cooled for codexUpstreamWebsocketCooldown
//     so a broken transport does not add latency to every request.
//   - Mid-stream failure (after any event reached the client): the request
//     fails. Partial output is never silently replayed over HTTP.

const codexUpstreamWebsocketCooldown = 5 * time.Minute

type codexUpstreamWebsocketDecoupledKey struct{}

// withCodexUpstreamWebsocketDecoupled marks the request as decoupled-mode
// (HTTP downstream, websocket upstream) so the websocket executor's failure
// paths know a transparent HTTP fallback is permissible.
func withCodexUpstreamWebsocketDecoupled(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, codexUpstreamWebsocketDecoupledKey{}, true)
}

func codexUpstreamWebsocketDecoupled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, _ := ctx.Value(codexUpstreamWebsocketDecoupledKey{}).(bool)
	return enabled
}

// codexUpstreamWebsocketCooldownMu guards wsCooldownUntil.
// Failures are rare; a single mutex is enough.
var codexUpstreamWebsocketCooldownMu sync.Mutex
var codexUpstreamWebsocketCooldownUntil = make(map[string]time.Time)

// codexUpstreamWebsocketCooling reports whether the credential's upstream
// websocket path is currently in its post-failure cooldown.
func codexUpstreamWebsocketCooling(authID string, now time.Time) bool {
	if authID == "" {
		return false
	}
	codexUpstreamWebsocketCooldownMu.Lock()
	defer codexUpstreamWebsocketCooldownMu.Unlock()
	until, ok := codexUpstreamWebsocketCooldownUntil[authID]
	if !ok {
		return false
	}
	if !until.After(now) {
		delete(codexUpstreamWebsocketCooldownUntil, authID)
		return false
	}
	return true
}

func noteCodexUpstreamWebsocketCooldown(authID string, now time.Time) {
	if authID == "" {
		return
	}
	codexUpstreamWebsocketCooldownMu.Lock()
	codexUpstreamWebsocketCooldownUntil[authID] = now.Add(codexUpstreamWebsocketCooldown)
	codexUpstreamWebsocketCooldownMu.Unlock()
}

// codexWebsocketDialFailureAllowsHTTPFallback decides whether a failed
// websocket dial/handshake may retry over HTTP in decoupled mode. Pure
// transport failures (no HTTP response), 5xx, 403, 408 and 426 qualify;
// auth (401), quota (429) or client-error (4xx) handshake responses must flow
// back unchanged so cooldown/quota semantics see the real status.
func codexWebsocketDialFailureAllowsHTTPFallback(respHS *http.Response) bool {
	if respHS == nil || respHS.StatusCode == 0 {
		return true // no handshake at all: DNS/TCP/TLS failure
	}
	switch {
	case respHS.StatusCode == http.StatusUpgradeRequired,
		respHS.StatusCode == http.StatusForbidden,
		respHS.StatusCode == http.StatusRequestTimeout,
		respHS.StatusCode >= 500:
		return true
	default:
		return false
	}
}

// decoupledCodexWebsocketSessionID computes the upstream-websocket session key
// for an HTTP/SSE client. Reusing the canonical session identity (computed by
// the session-affinity layer from session ids / prompt_cache_key / content
// hashes) keeps connection reuse aligned with prompt-cache locality: requests
// the selector would pin to one credential also share one socket.
func decoupledCodexWebsocketSessionID(opts cliproxyexecutor.Options) string {
	if len(opts.Metadata) == 0 {
		return ""
	}
	if canonical, ok := opts.Metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey].(string); ok {
		if canonical = strings.TrimSpace(canonical); canonical != "" {
			return "decws:" + canonical
		}
	}
	if lcp, ok := opts.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey].(string); ok {
		if lcp = strings.TrimSpace(lcp); lcp != "" {
			return "decws:" + lcp
		}
	}
	return ""
}

// ensureDecoupledCodexSessionID injects the derived session id into the
// execution options when the caller did not provide one, so the websocket
// executor reuses the persistent connection for this session.
func ensureDecoupledCodexSessionID(opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if len(opts.Metadata) > 0 {
		if raw, ok := opts.Metadata[cliproxyexecutor.ExecutionSessionMetadataKey]; ok {
			if s, _ := raw.(string); strings.TrimSpace(s) != "" {
				return opts
			}
		}
	}
	sessionID := decoupledCodexWebsocketSessionID(opts)
	if sessionID == "" {
		return opts
	}
	opts.EnsureMetadata()
	metadata := make(map[string]any, len(opts.Metadata)+1)
	for k, v := range opts.Metadata {
		metadata[k] = v
	}
	metadata[cliproxyexecutor.ExecutionSessionMetadataKey] = sessionID
	opts.Metadata = metadata
	return opts
}

// codexUpstreamWebsocketsConfigured reports whether the runtime config enables
// decoupled upstream websockets.
func codexUpstreamWebsocketsConfigured(cfg *config.Config) bool {
	return cfg != nil && cfg.Codex.UpstreamWebsockets
}

// codexDecoupledShouldFallbackWS reports whether a pre-stream websocket failure
// in decoupled mode may be retried once over HTTP. respHS is nil for pure
// transport failures (dial, write) and the handshake response otherwise.
// Requests bound to an execution lifecycle are excluded: their cleanup owns
// connector teardown.
func codexDecoupledShouldFallbackWS(ctx context.Context, opts cliproxyexecutor.Options, respHS *http.Response) bool {
	return codexUpstreamWebsocketDecoupled(ctx) && opts.ExecutionLifecycle == nil && codexWebsocketDialFailureAllowsHTTPFallback(respHS)
}

// codexDecoupledHTTPFallbackExecute runs the request through the legacy HTTP
// executor and cools the credential's websocket path. Only valid before any
// upstream event reached the client.
func (e *CodexWebsocketsExecutor) codexDecoupledHTTPFallbackExecute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if auth != nil {
		noteCodexUpstreamWebsocketCooldown(auth.ID, time.Now())
	}
	return e.CodexExecutor.Execute(ctx, auth, req, opts)
}

func (e *CodexWebsocketsExecutor) codexDecoupledHTTPFallbackStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if auth != nil {
		noteCodexUpstreamWebsocketCooldown(auth.ID, time.Now())
	}
	return e.CodexExecutor.ExecuteStream(ctx, auth, req, opts)
}
