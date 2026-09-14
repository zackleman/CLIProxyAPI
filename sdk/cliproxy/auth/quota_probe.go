package auth

import "time"

// QuotaWindowState captures one usage window learned from a proactive upstream
// quota probe (Claude /api/oauth/usage or Codex /wham/usage).
//
// UsedPercent is a pointer so "window present but unknown" and "0%" stay
// distinguishable; a nil percent never marks a credential exhausted.
// ResetsAt is the absolute reset timestamp reported by upstream. Weekly use
// recurs with a fixed cadence, so callers may project it forward instead of
// treating old data as unknown.
type QuotaWindowState struct {
	UsedPercent *float64  `json:"used_percent,omitempty"`
	ResetsAt    time.Time `json:"resets_at,omitempty"`
	IsActive    bool      `json:"is_active,omitempty"`
}

// QuotaProbe is a server-side snapshot of upstream quota windows for one
// credential. Passive header observations stay in QuotaState.Signals; the
// probe is the proactive counterpart that the polite rate-limit headers do
// not carry (for example Claude's per-model Fable weekly limit).
type QuotaProbe struct {
	FetchedAt time.Time                   `json:"fetched_at"`
	Windows   map[string]QuotaWindowState `json:"windows,omitempty"`
}

// Probe window names. Claude windows keep the /api/oauth/usage key names; the
// per-model Fable weekly entry from limits[] is flattened into
// QuotaWindowClaudeFable. Codex windows use the /wham/usage bucket names.
const (
	QuotaWindowClaudeFiveHour        = "five_hour"
	QuotaWindowClaudeSevenDay        = "seven_day"
	QuotaWindowClaudeSevenDayOpus    = "seven_day_opus"
	QuotaWindowClaudeSevenDaySonnet  = "seven_day_sonnet"
	QuotaWindowClaudeFable           = "fable_weekly"
	QuotaWindowCodexPrimary          = "primary"
	QuotaWindowCodexSecondary        = "secondary"
	QuotaWindowCodexAdditionalPrefix = "additional:"
)

// quotaProbeStaleAfter bounds how long a probe's utilisation data is trusted.
// Past this age the percent values are treated as unknown (reset timestamps
// stay usable through recurrence projection).
const quotaProbeStaleAfter = 2 * time.Hour

// fableWindowRecurrence is Anthropic's weekly reset cadence for the Fable
// window. Anthropic currently reports no interval; if that changes the
// projection must be revisited.
const fableWindowRecurrence = 7 * 24 * time.Hour

func (p *QuotaProbe) clone() *QuotaProbe {
	if p == nil {
		return nil
	}
	copied := &QuotaProbe{FetchedAt: p.FetchedAt}
	if len(p.Windows) > 0 {
		copied.Windows = make(map[string]QuotaWindowState, len(p.Windows))
		for name, window := range p.Windows {
			copied.Windows[name] = window
		}
	}
	return copied
}

// fresh reports whether the probe was fetched recently enough for percent
// values to be trusted.
func (p *QuotaProbe) fresh(now time.Time) bool {
	return p != nil && !p.FetchedAt.IsZero() && !p.FetchedAt.After(now) && now.Sub(p.FetchedAt) <= quotaProbeStaleAfter
}

// window returns the named window when present.
func (p *QuotaProbe) window(name string) (QuotaWindowState, bool) {
	if p == nil || p.Windows == nil {
		return QuotaWindowState{}, false
	}
	window, ok := p.Windows[name]
	return window, ok
}

// exhausted reports whether the named window has no quota left. Percent data
// older than quotaProbeStaleAfter is treated as unknown (not exhausted),
// because a weekly reset almost certainly moved the number since.
func (p *QuotaProbe) exhausted(name string, now time.Time) bool {
	window, ok := p.window(name)
	if !ok || !p.fresh(now) || window.UsedPercent == nil {
		return false
	}
	return *window.UsedPercent >= 100
}

// nextReset returns the next upcoming reset for the named window, projecting
// forward by recurrence once the learned timestamp has passed. Zero when no
// reset has ever been observed.
func (p *QuotaProbe) nextReset(name string, now time.Time, recurrence time.Duration) time.Time {
	window, ok := p.window(name)
	if !ok || window.ResetsAt.IsZero() {
		return time.Time{}
	}
	next := window.ResetsAt
	if recurrence <= 0 {
		return next
	}
	for !next.After(now) {
		next = next.Add(recurrence)
	}
	return next
}

// ----- Claude model-family routing accessors -----

// claudeFableExhausted reports whether this credential's Fable weekly quota
// is spent according to the latest probe.
func (q QuotaState) claudeFableExhausted(now time.Time) bool {
	return q.Probe.exhausted(QuotaWindowClaudeFable, now)
}

// claudeFableNextReset returns the credential's next upcoming Fable weekly
// reset, projected forward on the weekly cadence. Zero when unknown.
func (q QuotaState) claudeFableNextReset(now time.Time) time.Time {
	if q.Probe == nil {
		return time.Time{}
	}
	return q.Probe.nextReset(QuotaWindowClaudeFable, now, fableWindowRecurrence)
}
