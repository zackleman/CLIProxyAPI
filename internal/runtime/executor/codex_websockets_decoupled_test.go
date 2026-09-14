package executor

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func decoupledTestAuth(id string, websockets bool) *cliproxyauth.Auth {
	auth := &cliproxyauth.Auth{ID: id, Provider: "codex"}
	if websockets {
		auth.Attributes = map[string]string{"websockets": "true"}
	}
	return auth
}

func decoupledTestExecutor(cfg *config.Config) *CodexAutoExecutor {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return NewCodexAutoExecutor(cfg)
}

func TestUseUpstreamWebsocketGating(t *testing.T) {
	wsCtx := cliproxyexecutor.WithDownstreamWebsocket(context.Background())

	// Classic path: downstream WS always wins regardless of the new flag.
	exec := decoupledTestExecutor(&config.Config{})
	if !exec.useUpstreamWebsocket(wsCtx, decoupledTestAuth("g1", true)) {
		t.Fatal("downstream websocket client must ride websocket upstream without the flag")
	}

	// Flag off, HTTP client: never.
	if exec.useUpstreamWebsocket(context.Background(), decoupledTestAuth("g2", true)) {
		t.Fatal("decoupled mode must stay off without codex.upstream-websockets")
	}

	// Flag on: only for websocket-enabled credentials.
	exec = decoupledTestExecutor(&config.Config{Codex: config.CodexConfig{UpstreamWebsockets: true}})
	if !exec.useUpstreamWebsocket(context.Background(), decoupledTestAuth("g3", true)) {
		t.Fatal("decoupled mode must engage for websocket-enabled credentials")
	}
	if exec.useUpstreamWebsocket(context.Background(), decoupledTestAuth("g4", false)) {
		t.Fatal("decoupled mode must require the per-credential websockets attribute")
	}

	// Credential in websocket cooldown: falls back to HTTP.
	noteCodexUpstreamWebsocketCooldown("g5", time.Now())
	if exec.useUpstreamWebsocket(context.Background(), decoupledTestAuth("g5", true)) {
		t.Fatal("decoupled mode must skip credentials in websocket cooldown")
	}
}

func TestCodexUpstreamWebsocketCooldownExpires(t *testing.T) {
	now := time.Now()
	noteCodexUpstreamWebsocketCooldown("cooldown-expiry", now)
	if !codexUpstreamWebsocketCooling("cooldown-expiry", now.Add(time.Minute)) {
		t.Fatal("credential must be cooling at +1m")
	}
	if codexUpstreamWebsocketCooling("cooldown-expiry", now.Add(codexUpstreamWebsocketCooldown+time.Minute)) {
		t.Fatal("credential must leave cooldown after 5m")
	}
	if codexUpstreamWebsocketCooling("", now) || codexUpstreamWebsocketCooling("never-marked", now) {
		t.Fatal("unknown credentials must never report cooling")
	}
}

func TestCodexWebsocketDialFailureAllowsHTTPFallback(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   bool
	}{
		{"no handshake response (transport failure)", 0, true},
		{"upgrade required", http.StatusUpgradeRequired, true},
		{"cloudflare forbidden", http.StatusForbidden, true},
		{"request timeout", http.StatusRequestTimeout, true},
		{"server error", 503, true},
		{"auth failure must propagate", http.StatusUnauthorized, false},
		{"quota rejection must propagate", http.StatusTooManyRequests, false},
		{"client error must propagate", http.StatusBadRequest, false},
		{"payment error must propagate", http.StatusPaymentRequired, false},
		{"ok status is not a failure", 200, false}, // for completeness
	}
	for _, tc := range cases {
		var resp *http.Response
		if tc.status != 0 {
			resp = &http.Response{StatusCode: tc.status}
		}
		if got := codexWebsocketDialFailureAllowsHTTPFallback(resp); got != tc.want {
			t.Errorf("%s: dialFailureAllowsHTTPFallback(%d) = %v, want %v", tc.name, tc.status, got, tc.want)
		}
	}
}

func TestDecoupledSessionIDDerivation(t *testing.T) {
	// Canonical session id wins (set by the session-affinity layer).
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.CanonicalSessionIDMetadataKey:   "canon-1",
		cliproxyexecutor.LCPAffinitySessionIDMetadataKey: "lcp-ignored",
	}}
	if got := decoupledCodexWebsocketSessionID(opts); got != "decws:canon-1" {
		t.Fatalf("canonical session id = %q, want decws:canon-1", got)
	}

	// LCP fallback when canonical is missing.
	opts = cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.LCPAffinitySessionIDMetadataKey: "lcp-9",
	}}
	if got := decoupledCodexWebsocketSessionID(opts); got != "decws:lcp-9" {
		t.Fatalf("lcp fallback = %q, want decws:lcp-9", got)
	}

	// Nothing: no session (per-request connection, still correct).
	if got := decoupledCodexWebsocketSessionID(cliproxyexecutor.Options{}); got != "" {
		t.Fatalf("empty metadata must not derive a session id, got %q", got)
	}
}

func TestEnsureDecoupledSessionID(t *testing.T) {
	// Caller's own execution session id is authoritative.
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.ExecutionSessionMetadataKey:     "client-session",
		cliproxyexecutor.CanonicalSessionIDMetadataKey:   "canon-2",
		cliproxyexecutor.LCPAffinitySessionIDMetadataKey: "lcp-2",
		cliproxyexecutor.SessionAffinityModelMetadataKey: "gpt-5.3-codex",
	}}
	got := ensureDecoupledCodexSessionID(opts)
	if got.Metadata[cliproxyexecutor.ExecutionSessionMetadataKey] != "client-session" {
		t.Fatalf("explicit execution session id must be preserved, got %v", got.Metadata[cliproxyexecutor.ExecutionSessionMetadataKey])
	}

	// Derived id is injected, and the input metadata map is not aliased.
	original := map[string]any{cliproxyexecutor.CanonicalSessionIDMetadataKey: "canon-3"}
	opts = cliproxyexecutor.Options{Metadata: original}
	got = ensureDecoupledCodexSessionID(opts)
	if got.Metadata[cliproxyexecutor.ExecutionSessionMetadataKey] != "decws:canon-3" {
		t.Fatalf("derived session id = %v", got.Metadata[cliproxyexecutor.ExecutionSessionMetadataKey])
	}
	if _, exists := original[cliproxyexecutor.ExecutionSessionMetadataKey]; exists {
		t.Fatal("injection must copy, not mutate the caller's metadata map")
	}
}

func TestWebsocketSessionStoreIdleEviction(t *testing.T) {
	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	exec := &CodexWebsocketsExecutor{store: store}

	first := exec.getOrCreateSession("idle-evict")
	if first == nil {
		t.Fatal("session creation returned nil")
	}
	if again := exec.getOrCreateSession("idle-evict"); again != first {
		t.Fatal("fresh session must be reused")
	}

	// Simulate long-idle session: next access evicts and replaces.
	first.lastUsedUnix.Store(time.Now().Add(-2 * codexWebsocketSessionIdleTTL).Unix())
	replaced := exec.getOrCreateSession("idle-evict")
	if replaced == nil {
		t.Fatal("session creation after eviction returned nil")
	}
	if replaced == first {
		t.Fatal("idle-expired session must be replaced")
	}
}

func TestDecoupledCtxFlag(t *testing.T) {
	if codexUpstreamWebsocketDecoupled(context.Background()) {
		t.Fatal("decoupled flag must default off")
	}
	ctx := withCodexUpstreamWebsocketDecoupled(nil) // nil ctx tolerated
	if !codexUpstreamWebsocketDecoupled(ctx) {
		t.Fatal("decoupled flag lost")
	}
	// The decoupled flag must not affect guard rails shared with WS clients.
	if codexDecoupledShouldFallbackWS(ctx,
		cliproxyexecutor.Options{ExecutionLifecycle: noopExecutionLifecycle{}}, nil) {
		t.Fatal("lifecycle-bound requests must never fall back mid-ownership")
	}
}

type noopExecutionLifecycle struct{}

func (noopExecutionLifecycle) Bind(func() error) error { return nil }
func (noopExecutionLifecycle) End(string)              {}
