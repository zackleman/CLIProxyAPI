package helps

import (
	"context"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// DoQuotaProbeRequest executes one proactive quota probe GET for a credential
// using the fingerprinted, proxy-aware client Anthropic and chatgpt.com expect.
// The conductor's quota poller calls this through the injected
// cliproxyauth.QuotaProbeHTTPDoer hook (the auth package cannot import this
// package without an import cycle).
func DoQuotaProbeRequest(ctx context.Context, req *http.Request, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) (*http.Response, error) {
	client := NewUtlsHTTPClient(ctx, cfg, auth, timeout)
	return client.Do(req)
}
