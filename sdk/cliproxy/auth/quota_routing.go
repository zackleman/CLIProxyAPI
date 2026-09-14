package auth

import (
	"context"
	"sort"
	"strings"
	"time"
)

// Quota-aware routing rules (plan docs/plans/2026-09-13-fable-quota-routing-and-codex-ws.md):
//
//   - Fable requests: prefer the credential whose weekly Fable quota resets
//     soonest, as a strict primary ordering above the priority attribute, then
//     rotate among ties with the configured strategy.
//   - Opus requests: prefer credentials whose Fable weekly quota is exhausted
//     (Fable quota is otherwise unusable), then fall back to the rest.
//
// Both rules are Claude-only and gated on the quota-aware-routing config flag.
// Credentials without probe data are treated as "unknown": they keep quota for
// Fable purposes and sort as resetting latest.

const (
	claudeModelFamilyPrefixFable = "claude-fable"
	claudeModelFamilyPrefixOpus  = "claude-opus"
)

type quotaAwareRoutingKey struct{}

// withQuotaAwareRouting marks the selection context as quota-aware routing
// enabled. The manager injects this once per request from the runtime config;
// selectors and the scheduler read the flag from ctx so no config snapshot
// needs to be plumbed into their constructors.
func withQuotaAwareRouting(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, quotaAwareRoutingKey{}, true)
}

func quotaAwareRoutingEnabled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, _ := ctx.Value(quotaAwareRoutingKey{}).(bool)
	return enabled
}

// claudeQuotaRoutingFamily reports the quota-routing rule family for the
// (already alias-resolved) model: "fable", "opus", or "" when the model does
// not participate in quota-aware routing.
func claudeQuotaRoutingFamily(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	switch {
	case strings.HasPrefix(model, claudeModelFamilyPrefixFable):
		return "fable"
	case strings.HasPrefix(model, claudeModelFamilyPrefixOpus):
		return "opus"
	default:
		return ""
	}
}

// codexModelFamily reports whether the model name is a Codex-shaped model
// (the codex provider's dynamic catalog is always gpt-*/codex-*), used when a
// mixed-provider selector pool must route Codex traffic through the quota
// rule.
func codexModelFamily(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(model, "gpt") || strings.Contains(model, "codex")
}

// quotaProbeSortKey describes one credential's quota awareness for ordering:
// exhausted removes it outright for Fable requests; reset unknown sorts last.
type quotaProbeSortKey struct {
	auth      *Auth
	exhausted bool
	reset     time.Time
}

func quotaProbeSortKeyFor(auth *Auth, now time.Time) quotaProbeSortKey {
	key := quotaProbeSortKey{auth: auth}
	if auth == nil {
		return key
	}
	key.exhausted = auth.Quota.claudeFableExhausted(now)
	key.reset = auth.Quota.claudeFableNextReset(now)
	return key
}

// quotaAwareOrderForFable filters out Fable-exhausted credentials and orders
// the rest by soonest weekly reset (unknown resets last), then priority desc,
// then ID asc. It reports every credential as exhausted — and the soonest
// known reset across them — so callers can answer 429 + Retry-After without
// an upstream attempt.
func quotaAwareOrderForFable(auths []*Auth, now time.Time) (ordered []*Auth, allExcluded bool, soonestReset time.Time) {
	if len(auths) == 0 {
		return auths, false, time.Time{}
	}
	keys := make([]quotaProbeSortKey, 0, len(auths))
	var excluded []quotaProbeSortKey
	for _, candidate := range auths {
		key := quotaProbeSortKeyFor(candidate, now)
		if key.exhausted {
			excluded = append(excluded, key)
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		for _, key := range excluded {
			if !key.reset.IsZero() && (soonestReset.IsZero() || key.reset.Before(soonestReset)) {
				soonestReset = key.reset
			}
		}
		return nil, true, soonestReset
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.reset.IsZero() != b.reset.IsZero() {
			// Unknown resets sort last: without data we cannot promise the
			// reset comes any sooner than a credential we know is imminent.
			return !a.reset.IsZero()
		}
		if !a.reset.IsZero() && !b.reset.IsZero() && !a.reset.Equal(b.reset) {
			return a.reset.Before(b.reset)
		}
		if pa, pb := authPriority(a.auth), authPriority(b.auth); pa != pb {
			return pa > pb
		}
		return a.auth.ID < b.auth.ID
	})
	ordered = make([]*Auth, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, key.auth)
	}
	return ordered, false, time.Time{}
}

// quotaAwarePreferFableExhaustedForOpus narrows the candidate list to
// Fable-exhausted credentials when any exist. Without one, the input ordering
// is left untouched so the configured strategy applies to the full list.
func quotaAwarePreferFableExhaustedForOpus(auths []*Auth, now time.Time) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	exhausted := make([]*Auth, 0, len(auths))
	for _, candidate := range auths {
		if candidate != nil && candidate.Quota.claudeFableExhausted(now) {
			exhausted = append(exhausted, candidate)
		}
	}
	if len(exhausted) == 0 {
		return auths
	}
	return exhausted
}

// ----- Codex weekly-first ordering -----

// codexWeeklySortKey captures one credential's Codex allowance for the
// "most weekly allowance left first" ordering. The 5-hour primary window is
// a demotion flag: a credential whose hourly bucket is spent can only 429
// until it resets, so it must never be the head pick while others have
// hourly headroom.
//
// Unlike the Fable rule nothing is excluded outright: a credential whose
// weekly subscription is spent (100%) sorts last, not "out" — accounts with
// pay-as-you-go credits exist precisely for that state, and the locked
// intent is "credits only after every subscription's allowance is used up".
type codexWeeklySortKey struct {
	auth             *Auth
	primaryExhausted bool
	percentKnown     bool
	percent          float64
}

func codexWeeklySortKeyFor(auth *Auth, now time.Time) codexWeeklySortKey {
	key := codexWeeklySortKey{auth: auth}
	if auth == nil {
		return key
	}
	key.primaryExhausted = auth.Quota.codexPrimaryExhausted(now)
	key.percent, key.percentKnown = auth.Quota.codexWeeklyUsedPercent(now)
	return key
}

// quotaAwareOrderForCodexWeek orders candidates so the credential with the
// most weekly allowance left (lowest fresh used_percent) leads: hourly-exhausted
// credentials below all others, then unknown allowances, then by weekly
// percent ascending, then priority desc, then ID asc. Rotation happens within
// the head group, so a credential with more spent weekly quota is only picked
// once every better credential is unavailable or ties it exactly.
func quotaAwareOrderForCodexWeek(auths []*Auth, now time.Time) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	keys := make([]codexWeeklySortKey, 0, len(auths))
	for _, candidate := range auths {
		keys = append(keys, codexWeeklySortKeyFor(candidate, now))
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.primaryExhausted != b.primaryExhausted {
			return !a.primaryExhausted
		}
		if a.percentKnown != b.percentKnown {
			return a.percentKnown
		}
		if a.percentKnown && b.percentKnown && a.percent != b.percent {
			return a.percent < b.percent
		}
		if pa, pb := authPriority(a.auth), authPriority(b.auth); pa != pb {
			return pa > pb
		}
		return a.auth.ID < b.auth.ID
	})
	ordered := make([]*Auth, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, key.auth)
	}
	return ordered
}

// quotaCodexHeadGroup returns the leading group of an ordered Codex candidate
// list that shares the head's (primary-exhaustion, weekly percent state,
// priority). Rotation later happens within this group so tiers with more
// weekly spent (or a spent hourly bucket) are only entered once every
// fresher credential leaves availability.
func quotaCodexHeadGroup(ordered []*Auth, now time.Time) []*Auth {
	if len(ordered) <= 1 {
		return ordered
	}
	head := codexWeeklySortKeyFor(ordered[0], now)
	headPriority := authPriority(ordered[0])
	end := 1
	for end < len(ordered) {
		candidate := codexWeeklySortKeyFor(ordered[end], now)
		if candidate.primaryExhausted != head.primaryExhausted ||
			candidate.percentKnown != head.percentKnown ||
			(head.percentKnown && candidate.percent != head.percent) ||
			authPriority(candidate.auth) != headPriority {
			break
		}
		end++
	}
	return ordered[:end]
}

// quotaHeadGroup dispatches the family-specific head group for rotation:
// pickers rotate within the head tier rather than the full ordered list, so
// quota ordering is a strict primary preference.
func quotaHeadGroup(family string, ordered []*Auth, now time.Time) []*Auth {
	switch family {
	case "fable":
		return quotaFableHeadGroup(ordered, now)
	case "codex":
		return quotaCodexHeadGroup(ordered, now)
	default:
		return ordered
	}
}

// quotaFableHeadGroup returns the leading group of an ordered Fable candidate
// list that shares the first entry's (reset, priority). Rotation later happens
// within this group so distinct reset tiers always prefer the sooner tier.
func quotaFableHeadGroup(ordered []*Auth, now time.Time) []*Auth {
	if len(ordered) <= 1 {
		return ordered
	}
	head := ordered[0]
	headReset := head.Quota.claudeFableNextReset(now)
	headPriority := authPriority(head)
	end := 1
	for end < len(ordered) {
		candidate := ordered[end]
		if !candidate.Quota.claudeFableNextReset(now).Equal(headReset) || authPriority(candidate) != headPriority {
			break
		}
		end++
	}
	return ordered[:end]
}

// rotateWithinGroup picks the next candidate by ID after lastID, wrapping
// around. Unlike successorIndex this does not assume ID-sorted input.
func rotateWithinGroup(group []*Auth, lastID string) *Auth {
	if len(group) == 0 {
		return nil
	}
	sorted := make([]*Auth, len(group))
	copy(sorted, group)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	idx := sort.Search(len(sorted), func(i int) bool { return sorted[i].ID > lastID })
	if idx >= len(sorted) {
		idx = 0
	}
	return sorted[idx]
}

// prepareQuotaAwarePick reports the quota-routing rule family for this pick
// and whether availability must span all priority tiers (Fable reset ordering
// and the Codex weekly-first ordering are strict primary keys, so they cannot
// work on the top tier alone).
//
// The provider gate additionally accepts "mixed": the legacy multi-provider
// path invokes the selector with the combined candidate pool under that key,
// and the rules are still model-shaped (probe state only ever exists on
// credentials of the matching provider, so foreign candidates sort as unknown
// and stay reachable as failback).
func prepareQuotaAwarePick(ctx context.Context, provider, model string) (family string, acrossPriorities bool) {
	if !quotaAwareRoutingEnabled(ctx) {
		return "", false
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	modelKey := canonicalModelKey(model)
	switch provider {
	case "claude":
		family = claudeQuotaRoutingFamily(modelKey)
	case "codex":
		family = "codex"
	case "mixed":
		family = claudeQuotaRoutingFamily(modelKey)
		if family == "" && codexModelFamily(modelKey) {
			family = "codex"
		}
	default:
		return "", false
	}
	return family, family == "fable" || family == "codex"
}

// applyQuotaAwareCandidates narrows an available list per the rule family.
//
// handled=true signals the caller that the returned list is quota-sorted
// (Fable): the caller must pick from its head group instead of applying the
// normal strategy over the whole list. For Opus handled=false and the caller
// continues with its normal strategy on the narrowed list. A non-nil error is
// returned when every credential's Fable quota is exhausted, so the client
// gets 429 + Retry-After without a wasted upstream attempt.
func applyQuotaAwareCandidates(family, provider, model string, auths []*Auth, now time.Time) ([]*Auth, bool, error) {
	switch family {
	case "opus":
		return quotaAwarePreferFableExhaustedForOpus(auths, now), false, nil
	case "codex":
		// Pure ordering: weekly-spent (credits-reliant) accounts sort last but
		// stay reachable once every subscription account leaves availability.
		return quotaAwareOrderForCodexWeek(auths, now), true, nil
	case "fable":
		ordered, allExcluded, soonest := quotaAwareOrderForFable(auths, now)
		if allExcluded {
			if soonest.IsZero() {
				return nil, true, &Error{Code: "auth_unavailable", Message: "all Claude credentials have their weekly Fable quota exhausted"}
			}
			resetIn := soonest.Sub(now)
			if resetIn < 0 {
				resetIn = 0
			}
			return nil, true, newModelCooldownError(model, provider, resetIn)
		}
		return ordered, true, nil
	default:
		return auths, false, nil
	}
}
