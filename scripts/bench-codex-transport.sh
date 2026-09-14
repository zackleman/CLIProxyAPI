#!/usr/bin/env bash
# bench-codex-transport.sh — replay a multi-turn Codex session against the proxy
# and measure wall time, TTFB, and prompt-cache behaviour, to compare plain HTTP
# upstream vs decoupled websocket upstream (codex.upstream-websockets).
#
# The transport switch is server-side; this script only talks HTTP to the proxy.
#
# Usage:
#   BENCH_TRANSPORT=http BASE_URL=http://100.120.243.49:8317 API_KEY=sk-... ./scripts/bench-codex-transport.sh
#
# Env: MODEL (default gpt-5.3-codex), TURNS (default 12), REPS (default 5).
# Output: one JSON summary line per rep + a final aggregate line (stdout).
# Requires: curl, jq.

set -euo pipefail

BASE_URL=${BASE_URL:?BASE_URL required (proxy base, e.g. http://host:8317)}
API_KEY=${API_KEY:?API_KEY required}
MODEL=${MODEL:-gpt-5.3-codex}
TURNS=${TURNS:-12}
REPS=${REPS:-5}
LABEL=${BENCH_TRANSPORT:-unknown}

INSTRUCTIONS='You are a benchmark harness assistant. Rules for every turn: if the turn text is exactly "bench: ping N", reply with the single token "pong N". Never call any tool. Never add commentary. This envelope exists to give the session a decently sized, stable instruction block so prompt caching has something to amortize across turns. The quick brown fox jumps over the lazy dog. '"$(printf 'bench-filler %.0s' $(seq 1 60))"

run_turn() {
  # $1: turn index, $2: input JSON array (items), $3: out sse file
  local turn=$1 input_json=$2 out=$3
  local body
  body=$(jq -n --arg model "$MODEL" --arg instructions "$INSTRUCTIONS" --argjson input "$input_json" \
    '{model: $model, instructions: $instructions, input: $input, stream: true,
      tools: [{type: "function", name: "bench_noop", description: "Does nothing.", parameters: {type: "object", properties: {}, additionalProperties: false}}]}')
  local start_ns end_ns
  start_ns=$(python3 -c 'import time; print(time.time_ns())')
  if ! curl -sS --no-buffer -m 300 -X POST "$BASE_URL/v1/responses" \
      -H "Content-Type: application/json" -H "Authorization: Bearer $API_KEY" \
      -d "$body" > "$out"; then
    echo "curl failed on turn $turn" >&2
    return 1
  fi
  end_ns=$(python3 -c 'import time; print(time.time_ns())')
  if grep -q '^{' "$out" && jq -e '.error' "$out" >/dev/null 2>&1; then
    echo "proxy error on turn $turn: $(head -c 300 "$out")" >&2
    return 1
  fi
  wall_ms=$(( (end_ns - start_ns) / 1000000 ))
  # TTFB: client-side approximation skipped (we stream to file); use upstream wall.
  echo "$wall_ms"
}

run_rep() {
  # $1: rep index; prints JSON line
  local rep=$1
  local tmpdir; tmpdir=$(mktemp -d)
  local input='[]'
  local total_wall=0
  local first_cached=-1 last_cached=-1 last_total_in=-1 turns_ok=0

  local turn=1
  while [ "$turn" -le "$TURNS" ]; do
    local user_text="bench: ping $rep-$turn"
    input=$(jq --arg t "$user_text" '. + [{type: "message", role: "user", content: [{type: "input_text", text: $t}]}]' <<<"$input")
    local sse="$tmpdir/turn-$turn.sse"
    local wall; wall=$(run_turn "$turn" "$input" "$sse")
    total_wall=$(( total_wall + wall ))

    # Completed response: capture output items + usage.
    local completed
    completed=$(grep '^data: ' "$sse" | sed 's/^data: //' | jq -c 'select(.type=="response.completed") | .response' | tail -1)
    if [ -z "$completed" ]; then
      echo "rep $rep turn $turn: no response.completed" >&2
      head -5 "$sse" >&2
      rm -rf "$tmpdir"
      return 1
    fi
    local cached total_in
    cached=$(jq -r '.usage.input_tokens_details.cached_tokens // 0' <<<"$completed")
    total_in=$(jq -r '.usage.input_tokens // 0' <<<"$completed")
    [ "$turn" -eq 1 ] && first_cached=$cached
    last_cached=$cached; last_total_in=$total_in

    # Append the model's output items to the transcript, and answer any tool
    # calls so later turns stay well-formed.
    input=$(jq --argjson out "$(jq '[.output[] | if .type == "reasoning" then empty else . end]' <<<"$completed")" '. + $out' <<<"$input")
    local calls
    calls=$(jq -c '[.output[] | select(.type=="function_call")]' <<<"$completed")
    if [ "$(jq length <<<"$calls")" -gt 0 ]; then
      input=$(jq --argjson calls "$calls" '. + [$calls[] | {type: "function_call_output", call_id: .call_id, output: "ok"}]' <<<"$input")
    fi
    turns_ok=$(( turns_ok + 1 ))
    turn=$(( turn + 1 ))
  done

  rm -rf "$tmpdir"
  jq -n --arg label "$LABEL" --argjson rep "$rep" --argjson wall "$total_wall" \
    --argjson cached_first "$first_cached" --argjson cached_last "$last_cached" \
    --argjson in_last "$last_total_in" --argjson turns "$turns_ok" \
    '{transport: $label, rep: $rep, total_wall_ms: $wall, turns: $turns,
      cached_first_turn: $cached_first, cached_last_turn: $cached_last, input_tokens_last_turn: $in_last,
      cache_share_last_turn: (if $in_last > 0 then ($cached_last / $in_last) else null end)}'
}

main() {
  local rep=1
  while [ "$rep" -le "$REPS" ]; do
    run_rep "$rep"
    rep=$(( rep + 1 ))
  done | tee /dev/stderr | jq -s --arg label "$LABEL" '
    {
      transport: $label,
      reps: length,
      mean_total_wall_ms: (map(.total_wall_ms) | add / length | round),
      mean_cache_share_last_turn: (map(.cache_share_last_turn) | add / length * 1000 | round / 1000),
      mean_cached_last_turn: (map(.cached_last_turn) | add / length | round)
    }'
}

main
