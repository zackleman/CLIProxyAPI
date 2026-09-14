package auth

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func claudeAuthWithFableProbe(id string, priority int, percent *float64, reset time.Time, fetchedAt time.Time) *Auth {
	auth := &Auth{ID: id, Provider: "claude", Status: StatusActive}
	if priority != 0 {
		auth.Attributes = map[string]string{"priority": stringInt(priority)}
	}
	if percent != nil || !reset.IsZero() {
		auth.Quota.Probe = &QuotaProbe{
			FetchedAt: fetchedAt,
			Windows: map[string]QuotaWindowState{
				QuotaWindowClaudeFable: {UsedPercent: percent, ResetsAt: reset},
			},
		}
	}
	return auth
}

func stringInt(v int) string { return strconv.Itoa(v) }

func TestQuotaAwareOrderForFable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-5 * time.Minute)

	exhausted := claudeAuthWithFableProbe("exhausted", 0, ptrFloat(100), now.Add(24*time.Hour), fresh)
	soonest := claudeAuthWithFableProbe("soonest", 0, ptrFloat(40), now.Add(2*time.Hour), fresh)
	later := claudeAuthWithFableProbe("later", 0, ptrFloat(10), now.Add(72*time.Hour), fresh)
	unknown := claudeAuthWithFableProbe("unknown", 0, nil, time.Time{}, now)

	ordered, allExcluded, _ := quotaAwareOrderForFable([]*Auth{later, unknown, exhausted, soonest}, now)
	if allExcluded {
		t.Fatal("allExcluded = true, want false")
	}
	gotIDs := make([]string, 0, len(ordered))
	for _, auth := range ordered {
		gotIDs = append(gotIDs, auth.ID)
	}
	want := []string{"soonest", "later", "unknown"}
	if len(gotIDs) != len(want) {
		t.Fatalf("ordered IDs = %v, want %v", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("ordered IDs = %v, want %v", gotIDs, want)
		}
	}
}

func TestQuotaAwareOrderForFableAllExcluded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-5 * time.Minute)
	soonReset := now.Add(3 * time.Hour)

	a := claudeAuthWithFableProbe("a", 0, ptrFloat(100), now.Add(72*time.Hour), fresh)
	b := claudeAuthWithFableProbe("b", 0, ptrFloat(100), soonReset, fresh)

	ordered, allExcluded, soonest := quotaAwareOrderForFable([]*Auth{a, b}, now)
	if len(ordered) != 0 || !allExcluded {
		t.Fatalf("ordered=%v allExcluded=%v, want empty+true", ordered, allExcluded)
	}
	if !soonest.Equal(soonReset) {
		t.Fatalf("soonestReset = %v, want %v", soonest, soonReset)
	}
}

func TestQuotaAwarePreferFableExhaustedForOpus(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-5 * time.Minute)

	exhausted := claudeAuthWithFableProbe("exhausted", 0, ptrFloat(100), now.Add(24*time.Hour), fresh)
	normal := claudeAuthWithFableProbe("normal", 0, ptrFloat(10), now.Add(24*time.Hour), fresh)

	got := quotaAwarePreferFableExhaustedForOpus([]*Auth{normal, exhausted}, now)
	if len(got) != 1 || got[0].ID != "exhausted" {
		t.Fatalf("narrowed = %v, want [exhausted]", got)
	}

	none := quotaAwarePreferFableExhaustedForOpus([]*Auth{normal}, now)
	if len(none) != 1 || none[0].ID != "normal" {
		t.Fatalf("no exhausted credential must leave the list untouched, got %v", none)
	}
}

func TestRoundRobinSelectorQuotaAwareFable(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("later", 10, ptrFloat(10), now.Add(72*time.Hour), fresh), // higher priority but resets later
		claudeAuthWithFableProbe("soonest", 0, ptrFloat(50), now.Add(2*time.Hour), fresh),
	}
	selector := &RoundRobinSelector{}
	ctx := withQuotaAwareRouting(context.Background())

	picked, err := selector.Pick(ctx, "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "soonest" {
		t.Fatalf("Fable pick = %s, want soonest (strict primary ordering above priority)", picked.ID)
	}

	// Feature disabled: the higher-priority credential wins as before.
	picked, err = selector.Pick(context.Background(), "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "later" {
		t.Fatalf("legacy pick = %s, want later (priority tier wins)", picked.ID)
	}
}

func TestRoundRobinSelectorQuotaAwareFableAllExhausted(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("a", 0, ptrFloat(100), now.Add(72*time.Hour), fresh),
		claudeAuthWithFableProbe("b", 0, ptrFloat(100), now.Add(3*time.Hour), fresh),
	}
	selector := &RoundRobinSelector{}
	ctx := withQuotaAwareRouting(context.Background())

	_, err := selector.Pick(ctx, "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, auths)
	var mc *modelCooldownError
	if !errors.As(err, &mc) {
		t.Fatalf("Pick() error = %v (%T), want *modelCooldownError", err, err)
	}
	if mc.resetIn > 3*time.Hour+time.Minute {
		t.Fatalf("resetIn = %v, want ~3h (soonest reset)", mc.resetIn)
	}
}

func TestRoundRobinSelectorQuotaAwareFableNonFableModelUntouched(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("priority-hi", 10, ptrFloat(10), now.Add(72*time.Hour), fresh),
		claudeAuthWithFableProbe("priority-lo", 0, ptrFloat(50), now.Add(2*time.Hour), fresh),
	}
	selector := &RoundRobinSelector{}
	ctx := withQuotaAwareRouting(context.Background())

	picked, err := selector.Pick(ctx, "claude", "claude-sonnet-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "priority-hi" {
		t.Fatalf("sonnet pick = %s, want priority-hi (rule must not touch other families)", picked.ID)
	}
}

// The legacy multi-provider selection path invokes selectors with provider
// "mixed"; quota rules must still apply there (nucbox deploys several Bedrock
// bridge credentials and session-affinity, so the live path is mixed).
func TestRoundRobinSelectorQuotaAwareMixedProvider(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("claude-healthy", 0, ptrFloat(31), now.Add(24*time.Hour), fresh),
		claudeAuthWithFableProbe("claude-spent", 0, ptrFloat(100), now.Add(48*time.Hour), fresh),
		{ID: "bedrock-fallback", Provider: "claude", Status: StatusActive, Attributes: map[string]string{"priority": "-10"}},
	}
	selector := &RoundRobinSelector{}
	ctx := withQuotaAwareRouting(context.Background())

	// Fable through "mixed": soonest-reset credential wins, the unprobed
	// Bedrock failback stays reachable but sorts last.
	picked, err := selector.Pick(ctx, "mixed", "claude-fable-5-1", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "claude-healthy" {
		t.Fatalf("mixed Fable pick = %s, want claude-healthy", picked.ID)
	}

	// Opus through "mixed": Fable-exhausted credentials are preferred.
	picked, err = selector.Pick(ctx, "mixed", "claude-opus-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "claude-spent" {
		t.Fatalf("mixed Opus pick = %s, want claude-spent", picked.ID)
	}
}

func TestRoundRobinSelectorQuotaAwareOpus(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("healthy", 0, ptrFloat(10), now.Add(24*time.Hour), fresh),
		claudeAuthWithFableProbe("fable-exhausted", 0, ptrFloat(100), now.Add(24*time.Hour), fresh),
	}
	selector := &RoundRobinSelector{}
	ctx := withQuotaAwareRouting(context.Background())

	picked, err := selector.Pick(ctx, "claude", "claude-opus-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "fable-exhausted" {
		t.Fatalf("Opus pick = %s, want fable-exhausted", picked.ID)
	}
}

func TestSchedulerQuotaAwareFable(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("sch-later", 10, ptrFloat(10), now.Add(72*time.Hour), fresh),
		claudeAuthWithFableProbe("sch-soonest", 0, ptrFloat(50), now.Add(2*time.Hour), fresh),
	}
	registerSchedulerModels(t, "claude", "claude-fable-5-1", "sch-later", "sch-soonest")
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, auths...)
	ctx := withQuotaAwareRouting(context.Background())

	picked, err := scheduler.pickSingle(ctx, "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, nil)
	if err != nil {
		t.Fatalf("pickSingle() error = %v", err)
	}
	if picked == nil || picked.ID != "sch-soonest" {
		t.Fatalf("scheduler Fable pick = %v, want sch-soonest", picked)
	}

	// Legacy path keeps priority behavior without the flag.
	schedulerLegacy := newSchedulerForTest(&RoundRobinSelector{}, auths...)
	picked, err = schedulerLegacy.pickSingle(context.Background(), "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, nil)
	if err != nil {
		t.Fatalf("pickSingle() error = %v", err)
	}
	if picked == nil || picked.ID != "sch-later" {
		t.Fatalf("legacy scheduler pick = %v, want sch-later", picked)
	}
}

func TestSchedulerQuotaAwareFableAllExhaustedError(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("sch-x", 0, ptrFloat(100), now.Add(6*time.Hour), fresh),
		claudeAuthWithFableProbe("sch-y", 0, ptrFloat(100), now.Add(2*time.Hour), fresh),
	}
	registerSchedulerModels(t, "claude", "claude-fable-5-1", "sch-x", "sch-y")
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, auths...)
	ctx := withQuotaAwareRouting(context.Background())

	_, err := scheduler.pickSingle(ctx, "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, nil)
	var mc *modelCooldownError
	if !errors.As(err, &mc) {
		t.Fatalf("pickSingle() error = %v (%T), want *modelCooldownError with soonest reset", err, err)
	}
	if mc.resetIn > 2*time.Hour+time.Minute {
		t.Fatalf("resetIn = %v, want ~2h", mc.resetIn)
	}
}

func TestSchedulerQuotaAwareOpus(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	auths := []*Auth{
		claudeAuthWithFableProbe("opus-healthy", 0, ptrFloat(5), now.Add(24*time.Hour), fresh),
		claudeAuthWithFableProbe("opus-spent", 0, ptrFloat(100), now.Add(24*time.Hour), fresh),
	}
	registerSchedulerModels(t, "claude", "claude-opus-5", "opus-healthy", "opus-spent")
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, auths...)
	ctx := withQuotaAwareRouting(context.Background())

	// Round-robin within the exhausted credential set: the spent credential
	// must win every pick while it is the only exhausted one.
	for i := 0; i < 3; i++ {
		picked, err := scheduler.pickSingle(ctx, "claude", "claude-opus-5", cliproxyexecutor.Options{}, nil)
		if err != nil {
			t.Fatalf("pickSingle() #%d error = %v", i, err)
		}
		if picked == nil || picked.ID != "opus-spent" {
			t.Fatalf("scheduler Opus pick #%d = %v, want opus-spent", i, picked)
		}
	}
}

func codexAuthWithProbe(id string, priority int, weekly, primary *float64, fetchedAt time.Time) *Auth {
	auth := &Auth{ID: id, Provider: "codex", Status: StatusActive}
	if priority != 0 {
		auth.Attributes = map[string]string{"priority": stringInt(priority)}
	}
	if weekly != nil || primary != nil {
		windows := make(map[string]QuotaWindowState, 2)
		if weekly != nil {
			windows[QuotaWindowCodexSecondary] = QuotaWindowState{UsedPercent: weekly}
		}
		if primary != nil {
			windows[QuotaWindowCodexPrimary] = QuotaWindowState{UsedPercent: primary}
		}
		auth.Quota.Probe = &QuotaProbe{FetchedAt: fetchedAt, Windows: windows}
	}
	return auth
}

func TestQuotaAwareOrderForCodexWeek(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	// credits-style account with a spent weekly subscription, higher priority
	// than the subscription accounts: ordering must sink it last, not exclude it.
	credits := codexAuthWithProbe("credits", 10, ptrFloat(100), ptrFloat(5), fresh)
	subB := codexAuthWithProbe("sub-b", 0, ptrFloat(40), ptrFloat(5), fresh)
	subA := codexAuthWithProbe("sub-a", 0, ptrFloat(10), ptrFloat(5), fresh)
	unknown := codexAuthWithProbe("unknown", 0, nil, nil, time.Time{})

	ordered := quotaAwareOrderForCodexWeek([]*Auth{credits, subB, unknown, subA}, now)
	want := []string{"sub-a", "sub-b", "credits", "unknown"}
	if len(ordered) != len(want) {
		t.Fatalf("ordered = %v, want %v (no credential may be excluded)", ordered, want)
	}
	for i := range want {
		if ordered[i].ID != want[i] {
			t.Fatalf("ordered = %v, want %v", ordered, want)
		}
	}
}

func TestQuotaAwareOrderForCodexWeekPrimaryExhaustedDemotes(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	// Hourly bucket spent — picking this account only produces 429s until the
	// 5-hour reset, so it must rank below an account with less weekly headroom.
	spentHourly := codexAuthWithProbe("spent-hourly", 0, ptrFloat(10), ptrFloat(100), fresh)
	healthyHourly := codexAuthWithProbe("healthy-hourly", 0, ptrFloat(90), ptrFloat(5), fresh)

	ordered := quotaAwareOrderForCodexWeek([]*Auth{spentHourly, healthyHourly}, now)
	if ordered[0].ID != "healthy-hourly" {
		t.Fatalf("ordered = %v, want healthy-hourly first (primary window exhausted demotes)", ordered)
	}
}

func TestQuotaAwareOrderForCodexWeekStaleProbeTreatedUnknown(t *testing.T) {
	t.Parallel()
	now := time.Now()
	stale := now.Add(-3 * time.Hour)
	fresh := now.Add(-5 * time.Minute)

	staleProbe := codexAuthWithProbe("stale", 0, ptrFloat(5), ptrFloat(5), stale)
	freshProbe := codexAuthWithProbe("fresh", 0, ptrFloat(90), ptrFloat(5), fresh)

	ordered := quotaAwareOrderForCodexWeek([]*Auth{staleProbe, freshProbe}, now)
	if ordered[0].ID != "fresh" {
		t.Fatalf("ordered = %v, want fresh first (stale percents are unknown, sort last)", ordered)
	}
}

func TestRoundRobinSelectorQuotaAwareCodexWeeklyFirst(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	// The credits account has a spent weekly subscription but the highest
	// priority: it must only serve after every subscription with weekly
	// allowance left leaves availability.
	credits := codexAuthWithProbe("credits", 10, ptrFloat(100), ptrFloat(5), fresh)
	subA := codexAuthWithProbe("sub-a", 0, ptrFloat(30), ptrFloat(5), fresh)
	subB := codexAuthWithProbe("sub-b", 0, ptrFloat(10), ptrFloat(5), fresh)
	selector := &RoundRobinSelector{}
	ctx := withQuotaAwareRouting(context.Background())

	// Lowest weekly percent leads; rotation stays inside the head tier, so
	// the credits account is never picked while a fresher subscription is ready.
	first, err := selector.Pick(ctx, "codex", "gpt-5.5", cliproxyexecutor.Options{}, []*Auth{credits, subB, subA})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if first.ID != "sub-b" {
		t.Fatalf("first pick = %s, want sub-b (most weekly allowance left)", first.ID)
	}
	for i := 0; i < 4; i++ {
		if credits.Disabled {
			break
		}
		// Simulate sub-b leaving availability: only then may credits serve.
		subB.Disabled = true
		subA.Disabled = true
		picked, errPick := selector.Pick(ctx, "codex", "gpt-5.5", cliproxyexecutor.Options{}, []*Auth{credits, subB, subA})
		if errPick != nil {
			t.Fatalf("Pick() error = %v", errPick)
		}
		if picked.ID != "credits" {
			t.Fatalf("fallback pick = %s, want credits as last resort", picked.ID)
		}
		break
	}

	// Flag off: priority tier wins as before.
	picked, err := selector.Pick(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, []*Auth{credits, subB, subA})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "credits" {
		t.Fatalf("legacy pick = %s, want credits (priority tier wins without the flag)", picked.ID)
	}
}

func TestRoundRobinSelectorQuotaAwareCodexMixedProvider(t *testing.T) {
	t.Parallel()
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	home := codexAuthWithProbe("home", 0, ptrFloat(95), ptrFloat(5), fresh)
	office := codexAuthWithProbe("office", 0, ptrFloat(35), ptrFloat(5), fresh)
	selector := &RoundRobinSelector{}
	ctx := withQuotaAwareRouting(context.Background())

	picked, err := selector.Pick(ctx, "mixed", "gpt-5.3-codex-spark", cliproxyexecutor.Options{}, []*Auth{home, office})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if picked.ID != "office" {
		t.Fatalf("mixed pick = %s, want office (Codex rule applies on the mixed pool)", picked.ID)
	}
}

func TestSchedulerQuotaAwareCodex(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-5 * time.Minute)

	credits := codexAuthWithProbe("sch-credits", 10, ptrFloat(100), ptrFloat(5), fresh)
	sub := codexAuthWithProbe("sch-sub", 0, ptrFloat(25), ptrFloat(5), fresh)
	registerSchedulerModels(t, "codex", "gpt-5.5", "sch-credits", "sch-sub")
	scheduler := newSchedulerForTest(&RoundRobinSelector{}, credits, sub)
	ctx := withQuotaAwareRouting(context.Background())

	picked, err := scheduler.pickSingle(ctx, "codex", "gpt-5.5", cliproxyexecutor.Options{}, nil)
	if err != nil {
		t.Fatalf("pickSingle() error = %v", err)
	}
	if picked == nil || picked.ID != "sch-sub" {
		t.Fatalf("scheduler codex pick = %v, want sch-sub (weekly-first over priority)", picked)
	}

	// Legacy path keeps priority behavior without the flag.
	legacy := newSchedulerForTest(&RoundRobinSelector{}, credits, sub)
	picked, err = legacy.pickSingle(context.Background(), "codex", "gpt-5.5", cliproxyexecutor.Options{}, nil)
	if err != nil {
		t.Fatalf("pickSingle() error = %v", err)
	}
	if picked == nil || picked.ID != "sch-credits" {
		t.Fatalf("legacy scheduler pick = %v, want sch-credits", picked)
	}
}

func TestQuotaPollJitterBounds(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"", "a", "b", "claude-x@example.com"} {
		got := quotaPollJitter(id, quotaProbeInterval)
		if got < 0 || got > quotaProbeInterval {
			t.Fatalf("jitter(%q) = %v out of [0,%v]", id, got, quotaProbeInterval)
		}
	}
}

func TestQuotaProbeTargetAuth(t *testing.T) {
	t.Parallel()
	oauth := &Auth{Provider: "claude", Metadata: map[string]any{"access_token": "sk-ant-oat01-abc", "refresh_token": "rt"}}
	if !quotaProbeTargetAuth(oauth) {
		t.Fatal("claude oauth credential must be polled")
	}
	apiKey := &Auth{Provider: "claude", Attributes: map[string]string{"api_key": "sk-ant-api03-xyz"}}
	if quotaProbeTargetAuth(apiKey) {
		t.Fatal("claude api-key credential must not be polled")
	}
	codex := &Auth{Provider: "codex", Metadata: map[string]any{"access_token": "at", "refresh_token": "rt", "account_id": "acct"}}
	if !quotaProbeTargetAuth(codex) {
		t.Fatal("codex oauth credential must be polled")
	}
	gemini := &Auth{Provider: "gemini", Metadata: map[string]any{"access_token": "anything"}}
	if quotaProbeTargetAuth(gemini) {
		t.Fatal("unsupported provider must not be polled")
	}
}
