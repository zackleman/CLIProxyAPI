package auth

import (
	"testing"
	"time"
)

func ptrFloat(v float64) *float64 { return &v }

func TestParseClaudeOAuthUsageProbe(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	body := []byte(`{
		"five_hour": {"utilization": 12.5, "resets_at": "2026-09-08T17:00:00Z"},
		"seven_day": {"utilization": 61, "resets_at": "2026-09-12T19:00:00Z"},
		"seven_day_opus": {"utilization": 34, "resets_at": "2026-09-14T10:00:00Z"},
		"limits": [
			{"kind": "weekly_scoped", "scope": {"model": {"display_name": "Fable 5"}}, "percent": 87, "resets_at": "2026-09-09T22:00:00Z", "is_active": true},
			{"kind": "monthly", "scope": {"account": {}}, "percent": 5}
		]
	}`)
	probe := parseClaudeOAuthUsageProbe(body, now)
	if probe == nil {
		t.Fatal("parseClaudeOAuthUsageProbe() = nil")
	}
	if !probe.FetchedAt.Equal(now) {
		t.Fatalf("FetchedAt = %v, want %v", probe.FetchedAt, now)
	}
	sevenDay, ok := probe.window(QuotaWindowClaudeSevenDay)
	if !ok || sevenDay.UsedPercent == nil || *sevenDay.UsedPercent != 61 {
		t.Fatalf("seven_day window = %+v", sevenDay)
	}
	fable, ok := probe.window(QuotaWindowClaudeFable)
	if !ok {
		t.Fatal("fable_weekly window missing")
	}
	if fable.UsedPercent == nil || *fable.UsedPercent != 87 {
		t.Fatalf("fable percent = %v", fable.UsedPercent)
	}
	wantReset := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	if !fable.ResetsAt.Equal(wantReset) {
		t.Fatalf("fable resets_at = %v, want %v", fable.ResetsAt, wantReset)
	}
	if !fable.IsActive {
		t.Fatal("fable is_active = false, want true")
	}
}

func TestParseClaudeOAuthUsageProbeToleratesUnknownShapes(t *testing.T) {
	t.Parallel()
	now := time.Now()
	if probe := parseClaudeOAuthUsageProbe([]byte(`[]`), now); probe != nil {
		t.Fatalf("array payload => %+v, want nil", probe)
	}
	if probe := parseClaudeOAuthUsageProbe([]byte(`{}`), now); probe != nil {
		t.Fatalf("empty object => %+v, want nil", probe)
	}
	if probe := parseClaudeOAuthUsageProbe(nil, now); probe != nil {
		t.Fatalf("nil payload => %+v, want nil", probe)
	}
}

func TestParseCodexWhamUsageProbe(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	body := []byte(`{
		"plan_type": "plus",
		"rate_limit": {
			"primary": {"used_percent": 42, "window_minutes": 300, "reset_at": 1757350000},
			"secondary": {"used_percent": 80, "window_minutes": 10080, "reset_after_seconds": 3600}
		},
		"additional_rate_limits": [
			{"limit_name": "GPT-5.3-Codex-Spark", "rate_limit": {"used_percent": 10, "reset_after_seconds": 300}}
		]
	}`)
	probe := parseCodexWhamUsageProbe(body, now)
	if probe == nil {
		t.Fatal("parseCodexWhamUsageProbe() = nil")
	}
	primary, ok := probe.window(QuotaWindowCodexPrimary)
	if !ok || primary.UsedPercent == nil || *primary.UsedPercent != 42 {
		t.Fatalf("primary window = %+v", primary)
	}
	if !primary.ResetsAt.Equal(time.Unix(1757350000, 0)) {
		t.Fatalf("primary reset_at = %v", primary.ResetsAt)
	}
	secondary, ok := probe.window(QuotaWindowCodexSecondary)
	if !ok {
		t.Fatal("secondary window missing")
	}
	if !secondary.ResetsAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("secondary reset = %v, want %v", secondary.ResetsAt, now.Add(time.Hour))
	}
	spark, ok := probe.window(QuotaWindowCodexAdditionalPrefix + "gpt-5.3-codex-spark")
	if !ok || spark.UsedPercent == nil || *spark.UsedPercent != 10 {
		t.Fatalf("additional window = %+v", spark)
	}
}

func TestQuotaProbeExhaustionAndStaleness(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	probe := &QuotaProbe{
		FetchedAt: now.Add(-30 * time.Minute),
		Windows:   map[string]QuotaWindowState{QuotaWindowClaudeFable: {UsedPercent: ptrFloat(100)}},
	}
	if !probe.exhausted(QuotaWindowClaudeFable, now) {
		t.Fatal("fresh 100%% window should be exhausted")
	}

	probe.FetchedAt = now.Add(-quotaProbeStaleAfter - time.Minute)
	if probe.exhausted(QuotaWindowClaudeFable, now) {
		t.Fatal("stale probe must not mark exhausted")
	}

	probe.FetchedAt = now
	probe.Windows[QuotaWindowClaudeFable] = QuotaWindowState{UsedPercent: ptrFloat(99.9)}
	if probe.exhausted(QuotaWindowClaudeFable, now) {
		t.Fatal("99.9%% must not count as exhausted")
	}

	probe.Windows[QuotaWindowClaudeFable] = QuotaWindowState{}
	if probe.exhausted(QuotaWindowClaudeFable, now) {
		t.Fatal("unknown percent must not count as exhausted")
	}
}

func TestQuotaProbeNextResetRecurrenceProjection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	probe := &QuotaProbe{
		FetchedAt: now.Add(-8 * 24 * time.Hour), // stale, but reset timestamps recur
		Windows: map[string]QuotaWindowState{
			QuotaWindowClaudeFable: {ResetsAt: now.Add(-6*24*time.Hour - 12*time.Hour)}, // reset 6.5 days ago
		},
	}
	got := probe.nextReset(QuotaWindowClaudeFable, now, fableWindowRecurrence)
	// Learned reset + 7d is in the past; project twice to the upcoming one.
	want := now.Add(12 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("projected reset = %v, want %v", got, want)
	}

	empty := &QuotaProbe{FetchedAt: now}
	if got := empty.nextReset(QuotaWindowClaudeFable, now, fableWindowRecurrence); !got.IsZero() {
		t.Fatalf("unknown window reset = %v, want zero", got)
	}
}

func TestQuotaProbeClone(t *testing.T) {
	t.Parallel()
	probe := &QuotaProbe{
		FetchedAt: time.Now(),
		Windows:   map[string]QuotaWindowState{QuotaWindowClaudeFable: {UsedPercent: ptrFloat(50)}},
	}
	cloned := probe.clone()
	*probe.Windows[QuotaWindowClaudeFable].UsedPercent = 99
	// Mutating the clone's map must not touch the original.
	cloned.Windows[QuotaWindowClaudeFable] = QuotaWindowState{UsedPercent: ptrFloat(1)}
	if *probe.Windows[QuotaWindowClaudeFable].UsedPercent != 99 {
		t.Fatalf("clone shares window map: original = %v", *probe.Windows[QuotaWindowClaudeFable].UsedPercent)
	}
}
