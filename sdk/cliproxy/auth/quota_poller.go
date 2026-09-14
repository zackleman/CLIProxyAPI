package auth

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	log "github.com/sirupsen/logrus"
)

// QuotaProbeHTTPDoer executes the usage GET for a credential. The conductor
// package cannot import the uTLS-capable executor helpers (import cycle), so
// the runtime wires in a fingerprinted, proxy-aware implementation via
// SetQuotaProbeHTTPDoer at service start. Without one the poller skips
// credentials quietly.
type QuotaProbeHTTPDoer func(ctx context.Context, req *http.Request, cfg *internalconfig.Config, auth *Auth, timeout time.Duration) (*http.Response, error)

var quotaProbeHTTPDoer atomic.Value // stores QuotaProbeHTTPDoer

// SetQuotaProbeHTTPDoer installs the HTTP implementation used by the quota
// probe poller. Passing nil disables polling.
func SetQuotaProbeHTTPDoer(doer QuotaProbeHTTPDoer) {
	if doer == nil {
		quotaProbeHTTPDoer = atomic.Value{}
		return
	}
	quotaProbeHTTPDoer.Store(doer)
}

func quotaProbeHTTPDoerValue() QuotaProbeHTTPDoer {
	if doer, ok := quotaProbeHTTPDoer.Load().(QuotaProbeHTTPDoer); ok {
		return doer
	}
	return nil
}

// Constants for the proactive quota poller (quota-aware-routing).
const (
	// quotaProbeInterval is how often each credential is polled. The endpoint
	// data moves at rate-limit cadence; faster polling buys nothing upstream.
	quotaProbeInterval = 10 * time.Minute
	// quotaPollWake caps the loop sleep so config reloads and forced refreshes
	// are noticed promptly.
	quotaPollWake = 1 * time.Minute
	// quotaProbeRequestTimeout bounds the credential-acquisition-class GET to
	// the upstream usage endpoints. (Proxy policy: timeouts only for
	// credential acquisition — this call is one.)
	quotaProbeRequestTimeout = 30 * time.Second
	// quotaForcePollMinInterval debounces per-credential forced polls so a
	// burst of 429s cannot turn into request amplification.
	quotaForcePollMinInterval = 1 * time.Minute
	// quotaProbeMaxBody caps upstream response sizes (defence in depth).
	quotaProbeMaxBody = 1 << 20
)

const (
	claudeOAuthUsageURL    = "https://api.anthropic.com/api/oauth/usage"
	claudeOAuthUsageBeta   = "oauth-2025-04-20"
	codexWhamUsageURL      = "https://chatgpt.com/backend-api/wham/usage"
	claudeOAuthTokenPrefix = "sk-ant-oat"
)

// quotaPollerLoop polls upstream usage endpoints per credential and stores the
// results on the auth's Quota.Probe. It is intentionally simpler than the
// auto-refresh loop: a periodic scan over m.auths with per-auth next-poll
// timestamps, a debounced force-refresh map, and a wake channel.
type quotaPollerLoop struct {
	manager *Manager
	store   *fileQuotaProbeStore

	mu        sync.Mutex
	nextPoll  map[string]time.Time
	forcePoll map[string]time.Time // authID -> last forced poll time
	wakeCh    chan struct{}
	restored  bool
}

func newQuotaPollerLoop(manager *Manager, authDir string) *quotaPollerLoop {
	return &quotaPollerLoop{
		manager:   manager,
		store:     newFileQuotaProbeStore(authDir, authDir),
		nextPoll:  make(map[string]time.Time),
		forcePoll: make(map[string]time.Time),
		wakeCh:    make(chan struct{}, 1),
	}
}

// StartQuotaPoller starts the background quota probe loop. It is safe to call
// unconditionally at service start: the loop no-ops unless the runtime config
// enables quota-aware-routing, and it is skipped in Home mode like the
// auto-refresh loop.
func (m *Manager) StartQuotaPoller(ctx context.Context) {
	if m == nil {
		return
	}
	if m.HomeEnabled() {
		return
	}
	m.mu.Lock()
	if m.quotaPollCancel != nil {
		m.mu.Unlock()
		return
	}
	authDir := ""
	if cfg := m.runtimeConfigSnapshot(); cfg != nil {
		authDir = cfg.AuthDir
	}
	loop := newQuotaPollerLoop(m, authDir)
	pollCtx, cancel := context.WithCancel(context.Background())
	m.quotaPollLoop = loop
	m.quotaPollCancel = cancel
	m.mu.Unlock()
	go loop.run(pollCtx)
	log.Info("quota probe poller started (waits for quota-aware-routing config)")
}

// StopQuotaPoller terminates the background quota probe loop.
func (m *Manager) StopQuotaPoller() {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel := m.quotaPollCancel
	m.quotaPollCancel = nil
	m.quotaPollLoop = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// queueQuotaProbeRefresh forces the given credential to be polled soon,
// debounced per credential. Called from MarkResult on quota-class upstream
// failures so a limit rejection is confirmed (and its reset learned) without
// waiting for the next scheduled poll.
func (m *Manager) queueQuotaProbeRefresh(authID string) {
	if m == nil || authID == "" {
		return
	}
	m.mu.RLock()
	loop := m.quotaPollLoop
	m.mu.RUnlock()
	if loop == nil {
		return
	}
	loop.mu.Lock()
	if last, ok := loop.forcePoll[authID]; ok && time.Since(last) < quotaForcePollMinInterval {
		loop.mu.Unlock()
		return
	}
	loop.forcePoll[authID] = time.Now()
	loop.nextPoll[authID] = time.Now()
	loop.mu.Unlock()
	select {
	case loop.wakeCh <- struct{}{}:
	default:
	}
}

func (l *quotaPollerLoop) run(ctx context.Context) {
	if l == nil || l.manager == nil {
		return
	}
	timer := time.NewTimer(quotaPollWake)
	defer timer.Stop()
	for {
		l.tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-l.wakeCh:
		case <-timer.C:
		}
		timer.Reset(quotaPollWake)
	}
}

func (l *quotaPollerLoop) tick(ctx context.Context, now time.Time) {
	m := l.manager
	cfg := m.runtimeConfigSnapshot()
	if cfg == nil || !cfg.QuotaAwareRouting {
		return
	}
	l.restoreProbesOnce(ctx)

	type dueAuth struct {
		auth    *Auth
		refresh bool
	}
	var due []dueAuth
	m.mu.RLock()
	for id, auth := range m.auths {
		if auth == nil || auth.Disabled || !quotaProbeTargetAuth(auth) {
			continue
		}
		next, scheduled := l.lookupNextPoll(id)
		if !scheduled {
			// First poll spreads credentials across the interval so a fresh
			// start never bursts one request per credential.
			next = now.Add(quotaPollJitter(id, quotaProbeInterval))
			l.scheduleNext(id, next)
		}
		if !next.After(now) {
			due = append(due, dueAuth{auth: auth.Clone(), refresh: !auth.HasValidAccessToken(now)})
		}
	}
	m.mu.RUnlock()

	for _, item := range due {
		if ctx.Err() != nil {
			return
		}
		if item.refresh {
			if _, errRefresh := m.refreshAuthForRequest(ctx, item.auth.ID, authAccessToken(item.auth)); errRefresh != nil {
				log.Debugf("quota poller: refresh for %s failed: %v", quotaProbeAuthLabel(item.auth), errRefresh)
				// Fall through: poll with the token we have; upstream answers
				// 401 for dead tokens and the auto-refresh loop owns the retry.
			}
			m.mu.RLock()
			if current := m.auths[item.auth.ID]; current != nil {
				item.auth = current.Clone()
			}
			m.mu.RUnlock()
		}
		probe, errPoll := l.pollAuthQuota(ctx, item.auth)
		if errPoll != nil {
			log.Debugf("quota poller: usage fetch for %s failed: %v", quotaProbeAuthLabel(item.auth), errPoll)
			l.scheduleNext(item.auth.ID, now.Add(quotaProbeInterval))
			continue
		}
		m.applyQuotaProbe(item.auth.ID, probe)
		l.scheduleNext(item.auth.ID, now.Add(quotaProbeInterval))
	}
}

func (l *quotaPollerLoop) lookupNextPoll(authID string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	next, ok := l.nextPoll[authID]
	return next, ok
}

func (l *quotaPollerLoop) scheduleNext(authID string, next time.Time) {
	l.mu.Lock()
	l.nextPoll[authID] = next
	l.mu.Unlock()
}

// quotaPollJitter scatters the first poll of each credential across the full
// interval, deterministically by auth ID.
func quotaPollJitter(authID string, interval time.Duration) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(authID))
	return time.Duration(int64(h.Sum32()) % interval.Nanoseconds())
}

// restoreProbesOnce attaches persisted .quota sidecars to freshly loaded
// credentials so ordering survives restarts before the first new poll lands.
func (l *quotaPollerLoop) restoreProbesOnce(ctx context.Context) {
	l.mu.Lock()
	if l.restored {
		l.mu.Unlock()
		return
	}
	l.restored = true
	l.mu.Unlock()

	probes := l.store.LoadAll(ctx)
	if len(probes) == 0 {
		return
	}
	restored := 0
	m := l.manager
	m.mu.Lock()
	for id, probe := range probes {
		auth := m.auths[id]
		if auth == nil || auth.Quota.Probe != nil {
			continue
		}
		auth.Quota.Probe = probe
		restored++
	}
	m.mu.Unlock()
	if restored > 0 {
		m.mu.RLock()
		snapshots := make([]*Auth, 0, len(probes))
		for id := range probes {
			if auth := m.auths[id]; auth != nil {
				snapshots = append(snapshots, auth.Clone())
			}
		}
		m.mu.RUnlock()
		if m.scheduler != nil {
			for _, snapshot := range snapshots {
				m.scheduler.upsertAuth(snapshot)
			}
		}
		log.Infof("quota poller: restored %d persisted quota probe(s)", restored)
	}
}

// applyQuotaProbe stores a fresh probe on the credential, persists the
// sidecar, and refreshes the scheduler snapshot so selection sees it.
func (m *Manager) applyQuotaProbe(authID string, probe *QuotaProbe) {
	if m == nil || probe == nil || authID == "" {
		return
	}
	m.mu.Lock()
	auth := m.auths[authID]
	if auth == nil {
		m.mu.Unlock()
		return
	}
	auth.Quota.Probe = probe
	snapshot := auth.Clone()
	store := m.quotaProbeStoreLocked()
	m.mu.Unlock()

	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	if store != nil {
		if errSave := store.Save(context.Background(), snapshot); errSave != nil {
			log.Warnf("quota poller: persisting probe for %s failed: %v", quotaProbeAuthLabel(snapshot), errSave)
		}
	}
}

func (m *Manager) quotaProbeStoreLocked() *fileQuotaProbeStore {
	if m.quotaPollLoop == nil {
		return nil
	}
	return m.quotaPollLoop.store
}

// withQuotaAwareRoutingContext returns a context carrying the quota-aware
// routing flag when the runtime config enables it. Selectors and the
// scheduler read the flag from context so no config snapshot is plumbed into
// their constructors. Home-managed selection is left untouched.
func (m *Manager) withQuotaAwareRoutingContext(ctx context.Context) context.Context {
	if m == nil || m.HomeEnabled() {
		return ctx
	}
	cfg := m.runtimeConfigSnapshot()
	if cfg == nil || !cfg.QuotaAwareRouting {
		return ctx
	}
	return withQuotaAwareRouting(ctx)
}

// quotaProbeTargetAuth reports whether the credential is pollable: a Claude
// OAuth token or a Codex OAuth token. API-key credentials are skipped.
func quotaProbeTargetAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		return strings.HasPrefix(authAccessToken(auth), claudeOAuthTokenPrefix)
	case "codex":
		return authAccessToken(auth) != "" && authHasRefreshCredential(auth)
	default:
		return false
	}
}

func quotaProbeAuthLabel(auth *Auth) string {
	if auth == nil {
		return "<nil>"
	}
	if label := strings.TrimSpace(auth.Label); label != "" {
		return label
	}
	return auth.ID
}

// pollAuthQuota fetches the upstream usage endpoint for one credential and
// parses it into a probe.
func (l *quotaPollerLoop) pollAuthQuota(ctx context.Context, auth *Auth) (*QuotaProbe, error) {
	if l == nil || auth == nil {
		return nil, fmt.Errorf("quota poller: nil")
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	var request *http.Request
	var errReq error
	token := authAccessToken(auth)
	if token == "" {
		return nil, fmt.Errorf("quota poller: no access token for %s", quotaProbeAuthLabel(auth))
	}
	switch provider {
	case "claude":
		request, errReq = http.NewRequestWithContext(ctx, http.MethodGet, claudeOAuthUsageURL, nil)
		if errReq == nil {
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Anthropic-Beta", claudeOAuthUsageBeta)
		}
	case "codex":
		request, errReq = http.NewRequestWithContext(ctx, http.MethodGet, codexWhamUsageURL, nil)
		if errReq == nil {
			request.Header.Set("Authorization", "Bearer "+token)
			if accountID := authMetadataString(auth, "account_id"); accountID != "" {
				request.Header.Set("Chatgpt-Account-Id", accountID)
			}
		}
	default:
		return nil, fmt.Errorf("quota poller: provider %q not pollable", provider)
	}
	if errReq != nil {
		return nil, errReq
	}

	doer := quotaProbeHTTPDoerValue()
	if doer == nil {
		return nil, fmt.Errorf("quota poller: no HTTP doer installed (SetQuotaProbeHTTPDoer not wired)")
	}
	cfg := l.manager.runtimeConfigSnapshot()
	resp, errDo := doer(ctx, request, cfg, auth, quotaProbeRequestTimeout)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("quota poller: closing response body failed: %v", errClose)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("quota poller: upstream status %s", resp.Status)
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, quotaProbeMaxBody+1))
	if errRead != nil {
		return nil, errRead
	}
	if int64(len(body)) > quotaProbeMaxBody {
		return nil, fmt.Errorf("quota poller: response over %d bytes", quotaProbeMaxBody)
	}
	switch provider {
	case "claude":
		return parseClaudeOAuthUsageProbe(body, time.Now()), nil
	case "codex":
		return parseCodexWhamUsageProbe(body, time.Now()), nil
	}
	return nil, fmt.Errorf("quota poller: provider %q not pollable", provider)
}
