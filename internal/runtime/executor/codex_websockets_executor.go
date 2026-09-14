// Package executor provides runtime execution capabilities for various AI service providers.
// This file implements a Codex executor that uses the Responses API WebSocket transport.
package executor

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// CodexWebsocketsExecutor executes Codex Responses requests using a WebSocket transport.
//
// It preserves the existing CodexExecutor HTTP implementation as a fallback for endpoints
// not available over WebSocket (e.g. /responses/compact) and for websocket upgrade failures.
type CodexWebsocketsExecutor struct {
	*CodexExecutor

	store *codexWebsocketSessionStore
}

func NewCodexWebsocketsExecutor(cfg *config.Config) *CodexWebsocketsExecutor {
	return &CodexWebsocketsExecutor{
		CodexExecutor: NewCodexExecutor(cfg),
		store:         globalCodexWebsocketSessionStore,
	}
}

// CodexAutoExecutor routes Codex requests to the websocket transport when:
//  1. The downstream transport is websocket and the auth enables websockets, or
//  2. codex.upstream-websockets is on, the auth enables websockets, and the
//     credential's websocket path is not in its post-failure cooldown
//     (decoupled mode: HTTP/SSE clients, persistent upstream socket).
//
// Otherwise it uses the legacy HTTP implementation.
type CodexAutoExecutor struct {
	httpExec *CodexExecutor
	wsExec   *CodexWebsocketsExecutor
	cfg      *config.Config
}

func NewCodexAutoExecutor(cfg *config.Config) *CodexAutoExecutor {
	return &CodexAutoExecutor{
		httpExec: NewCodexExecutor(cfg),
		wsExec:   NewCodexWebsocketsExecutor(cfg),
		cfg:      cfg,
	}
}

func (e *CodexAutoExecutor) Identifier() string { return "codex" }

func (e *CodexAutoExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if e == nil || e.httpExec == nil {
		return nil
	}
	return e.httpExec.PrepareRequest(req, auth)
}

func (e *CodexAutoExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if e == nil || e.httpExec == nil {
		return nil, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.HttpRequest(ctx, auth, req)
}

// runtimeConfig returns the freshest config: the conductor swaps executor configs
// on hot reload, so prefer the embedded executors' cfg and fall back to the
// construction-time snapshot.
// UsesConfig reports whether the executor already runs on this exact config
// snapshot, so hot reloads rebind the executor (and its decoupled-websocket
// gate) only when the service actually swapped configs.
func (e *CodexAutoExecutor) UsesConfig(cfg *config.Config) bool {
	return e != nil && e.httpExec != nil && e.httpExec.cfg == cfg
}

func (e *CodexAutoExecutor) runtimeConfig() *config.Config {
	if e == nil {
		return nil
	}
	if e.httpExec != nil && e.httpExec.cfg != nil {
		return e.httpExec.cfg
	}
	return e.cfg
}

// useUpstreamWebsocket reports whether this request should ride the websocket
// upstream, covering both classic mode (WS client) and decoupled mode.
func (e *CodexAutoExecutor) useUpstreamWebsocket(ctx context.Context, auth *cliproxyauth.Auth) bool {
	if !codexWebsocketsEnabled(auth) {
		return false
	}
	if cliproxyexecutor.DownstreamWebsocket(ctx) {
		return true
	}
	if !codexUpstreamWebsocketsConfigured(e.runtimeConfig()) {
		return false
	}
	if auth == nil || codexUpstreamWebsocketCooling(auth.ID, time.Now()) {
		return false
	}
	return true
}

// prepareDecoupled turns a decoupled-mode request options into a session-bearing
// one: HTTP clients carry no execution session id, so we derive one from the
// canonical session identity to reuse the persistent upstream connection.
func prepareDecoupled(ctx context.Context, opts cliproxyexecutor.Options) (context.Context, cliproxyexecutor.Options) {
	if cliproxyexecutor.DownstreamWebsocket(ctx) {
		return ctx, opts
	}
	return withCodexUpstreamWebsocketDecoupled(ctx), ensureDecoupledCodexSessionID(opts)
}

func (e *CodexAutoExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e == nil || e.httpExec == nil || e.wsExec == nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex auto executor: executor is nil")
	}
	if cliproxyexecutor.DownstreamWebsocket(ctx) && codexWebsocketsEnabled(auth) {
		return e.wsExec.Execute(ctx, auth, req, opts)
	}
	if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		return cliproxyexecutor.Response{}, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
	}
	if e.useUpstreamWebsocket(ctx, auth) {
		ctx, opts = prepareDecoupled(ctx, opts)
		return e.wsExec.Execute(ctx, auth, req, opts)
	}
	return e.httpExec.Execute(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if e == nil || e.httpExec == nil || e.wsExec == nil {
		return nil, fmt.Errorf("codex auto executor: executor is nil")
	}
	if cliproxyexecutor.DownstreamWebsocket(ctx) && codexWebsocketsEnabled(auth) {
		return e.wsExec.ExecuteStream(ctx, auth, req, opts)
	}
	if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		return nil, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
	}
	if e.useUpstreamWebsocket(ctx, auth) {
		ctx, opts = prepareDecoupled(ctx, opts)
		return e.wsExec.ExecuteStream(ctx, auth, req, opts)
	}
	return e.httpExec.ExecuteStream(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if e == nil || e.httpExec == nil {
		return nil, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.Refresh(ctx, auth)
}

func (e *CodexAutoExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e == nil || e.httpExec == nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.CountTokens(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) CloseExecutionSession(sessionID string) {
	if e == nil || e.wsExec == nil {
		return
	}
	e.wsExec.CloseExecutionSession(sessionID)
}

func (e *CodexAutoExecutor) UpstreamDisconnectChan(sessionID string) <-chan error {
	if e == nil || e.wsExec == nil {
		return nil
	}
	return e.wsExec.UpstreamDisconnectChan(sessionID)
}

func codexWebsocketsEnabled(auth *cliproxyauth.Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}
