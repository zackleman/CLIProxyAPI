package auth

import (
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// Proactive quota payload parsers. Both payload shapes are upstream-private
// (they are the same endpoints the management dashboard calls from the
// browser); the parsing is deliberately defensive and drops unknown keys.

// parseClaudeOAuthUsageProbe parses GET api.anthropic.com/api/oauth/usage.
//
// Known shape: per-window objects keyed five_hour / seven_day /
// seven_day_opus / seven_day_sonnet, each {"utilization": <0-100>,
// "resets_at": "<RFC3339>"}, plus a limits[] array where the per-model Fable
// weekly entry carries {"kind": "weekly_scoped", "scope": {"model": ...},
// "percent": <0-100>, "resets_at": ..., "is_active": true}. Plainly keyed
// windows are persisted verbatim by name; the Fable entry is flattened into
// QuotaWindowClaudeFable.
func parseClaudeOAuthUsageProbe(body []byte, now time.Time) *QuotaProbe {
	if len(body) == 0 {
		return nil
	}
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return nil
	}
	probe := &QuotaProbe{FetchedAt: now, Windows: make(map[string]QuotaWindowState)}
	root.ForEach(func(key, value gjson.Result) bool {
		name := key.String()
		if name == "limits" || !value.IsObject() {
			return true
		}
		if window, ok := parseUsageWindow(value, now); ok {
			probe.Windows[name] = window
		}
		return true
	})

	limits := root.Get("limits")
	if limits.IsArray() {
		limits.ForEach(func(_, entry gjson.Result) bool {
			if !claudeLimitEntryIsFableWeekly(entry) {
				return true
			}
			window, ok := parseUsageWindow(entry, now)
			if !ok {
				return true
			}
			window.IsActive = entry.Get("is_active").Bool()
			probe.Windows[QuotaWindowClaudeFable] = window
			return true
		})
	}
	if len(probe.Windows) == 0 {
		return nil
	}
	return probe
}

// claudeLimitEntryIsFableWeekly matches limits[] entries identifying the
// per-model Fable weekly window, tolerating the naming spellings observed in
// the dashboard's quota page detection (display_name "fable" / "fable 5").
func claudeLimitEntryIsFableWeekly(entry gjson.Result) bool {
	if !entry.IsObject() {
		return false
	}
	kind := strings.ToLower(entry.Get("kind").String())
	if !strings.Contains(kind, "weekly") {
		return false
	}
	modelText := strings.ToLower(
		entry.Get("scope").Raw + " " +
			entry.Get("scope_model").String() + " " +
			entry.Get("model").String())
	return strings.Contains(modelText, "fable")
}

// parseCodexWhamUsageProbe parses GET chatgpt.com/backend-api/wham/usage.
//
// Known shape: rate_limit{ primary{used_percent, window_minutes,
// reset_after_seconds, reset_at}, secondary{...} }, plan_type, credits,
// additional_rate_limits[]{limit_name, metered_feature, rate_limit{...}}.
func parseCodexWhamUsageProbe(body []byte, now time.Time) *QuotaProbe {
	if len(body) == 0 {
		return nil
	}
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return nil
	}
	probe := &QuotaProbe{FetchedAt: now, Windows: make(map[string]QuotaWindowState)}
	rateLimits := root.Get("rate_limit")
	if !rateLimits.Exists() {
		rateLimits = root.Get("rate_limits")
	}
	addCodexWindows(rateLimits, "", probe, now)
	additional := root.Get("additional_rate_limits")
	if additional.IsArray() {
		additional.ForEach(func(_, entry gjson.Result) bool {
			limitName := strings.TrimSpace(entry.Get("limit_name").String())
			if limitName == "" {
				limitName = strings.TrimSpace(entry.Get("metered_feature").String())
			}
			if limitName != "" {
				addCodexWindows(entry.Get("rate_limit"), QuotaWindowCodexAdditionalPrefix+strings.ToLower(limitName)+":", probe, now)
			}
			return true
		})
	}
	if len(probe.Windows) == 0 {
		return nil
	}
	return probe
}

// addCodexWindows extracts the primary/secondary windows from a Codex
// rate_limit object. Live payloads use primary_window / secondary_window; the
// bare spellings are kept for the header-flat variants.
func addCodexWindows(rateLimits gjson.Result, prefix string, probe *QuotaProbe, now time.Time) {
	for _, bucket := range []struct {
		keys []string
		name string
	}{
		{[]string{"primary_window", "primary"}, prefix + QuotaWindowCodexPrimary},
		{[]string{"secondary_window", "secondary"}, prefix + QuotaWindowCodexSecondary},
	} {
		for _, key := range bucket.keys {
			if window, ok := parseUsageWindow(rateLimits.Get(key), now); ok {
				probe.Windows[bucket.name] = window
				break
			}
		}
	}
}

// parseUsageWindow extracts percent/reset from the widely varying upstream
// window objects. Percent keys tried: used_percent, utilization, percent.
// Reset keys tried: resets_at (RFC3339), reset_at (RFC3339 or unix seconds),
// reset_after_seconds / resets_in_seconds (relative to now).
func parseUsageWindow(value gjson.Result, now time.Time) (QuotaWindowState, bool) {
	if !value.IsObject() {
		return QuotaWindowState{}, false
	}
	var window QuotaWindowState
	ok := false
	for _, key := range []string{"used_percent", "utilization", "percent"} {
		if result := value.Get(key); result.Exists() && result.Type == gjson.Number {
			percent := result.Float()
			window.UsedPercent = &percent
			ok = true
			break
		}
	}
	if reset := parseUsageResetAt(value); !reset.IsZero() {
		window.ResetsAt = reset
		ok = true
	} else if seconds := usageResetAfterSeconds(value); seconds > 0 {
		window.ResetsAt = now.Add(time.Duration(seconds) * time.Second)
		ok = true
	}
	return window, ok
}

func parseUsageResetAt(value gjson.Result) time.Time {
	for _, key := range []string{"resets_at", "reset_at"} {
		result := value.Get(key)
		if !result.Exists() {
			continue
		}
		if result.Type == gjson.Number {
			seconds := int64(result.Float())
			if seconds > 0 {
				return time.Unix(seconds, 0)
			}
			continue
		}
		if raw := strings.TrimSpace(result.String()); raw != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
				return parsed
			}
			if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}

func usageResetAfterSeconds(value gjson.Result) int64 {
	for _, key := range []string{"reset_after_seconds", "resets_in_seconds"} {
		if result := value.Get(key); result.Exists() && result.Type == gjson.Number {
			return int64(result.Float())
		}
	}
	return 0
}
