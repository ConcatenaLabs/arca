# operator-tests.sh load: many wallets of the operator paying each other out
# of round, the load raised step by step until something gives. Sourced by
# operator-tests.sh, which sets RUN, the wallets' helpers and the hooks.

# One worker: the wallets whose number is ID modulo C, each in turn paying
# a random other wallet one of its pre-made requests, until DEADLINE. Every
# command's wall time and outcome is one line of $RUN/load/sends.
load_worker() {
  local id=$1 c=$2 deadline=$3 step=$4 i s r req t0 t1 out ok n=0 used line
  local mine=() pool=()
  for i in $(seq 0 $((USERS - 1))); do [ $((i % c)) = "$id" ] && mine+=("$i"); done
  [ ${#mine[@]} = 0 ] && return 0
  mapfile -t pool < "$RUN/load/pool.$id"
  used=$(cat "$RUN/load/pool.$id.used" 2>/dev/null || echo 0)
  while [ "$(date +%s)" -lt "$deadline" ] && [ "$used" -lt "${#pool[@]}" ]; do
    s=${mine[$((n % ${#mine[@]}))]}; n=$((n + 1))
    # A wallet whose coins wait for their refresh syncs instead of paying.
    if [ -e "$RUN/load/refresh.$s" ]; then
      if arca "u$s" sync > /dev/null 2>&1 && \
         [ "$(arca "u$s" coins | jq --arg a "$ASSET" '[.[]|select(.asset==$a and .state=="live" and .hops<5)]|length')" -gt 0 ]; then
        rm -f "$RUN/load/refresh.$s"
      else
        sleep 1; continue
      fi
    fi
    line=${pool[$used]}; r=${line%% *}; req=${line#* }
    [ "$r" = "$s" ] && { used=$((used + 1)); continue; }
    used=$((used + 1)); echo "$used" > "$RUN/load/pool.$id.used"
    arca "u$s" mailbox > /dev/null 2>&1 || true
    t0=$(date +%s.%N)
    set +e; out=$(arca "u$s" send "$req" --amount "$PAY"); ok=$?; set -e
    t1=$(date +%s.%N)
    if [ $ok = 0 ]; then
      printf '%s %s %.4f ok -\n' "$step" "$t1" "$(awk "BEGIN{print $t1-$t0}")" >> "$RUN/load/sends.$id"
    else
      local why; why=$(jq -r '.error.message // "?"' <<<"$out" 2>/dev/null | tr ' \t' '__' | cut -c1-120)
      printf '%s %s %.4f err %s\n' "$step" "$t1" "$(awk "BEGIN{print $t1-$t0}")" "$why" >> "$RUN/load/sends.$id"
      # Coins too many reassignments from a round: refreshed in the next.
      case "$why" in
        *depth_limit*) arca "u$s" participate > /dev/null 2>&1 && touch "$RUN/load/refresh.$s" ;;
      esac
    fi
  done
}

# CPU seconds (user+system) and resident memory (kB) of the operator's
# processes and their children, one line each sample.
load_sample() {
  local pids p all=() tot_cpu=0 tot_rss=0 tck
  tck=$(getconf CLK_TCK)
  for p in $(operator_pids); do all+=("$p"); all+=($(pgrep -P "$p" 2>/dev/null || true)); done
  for p in "${all[@]}"; do
    [ -r "/proc/$p/stat" ] || continue
    read -r ut st < <(awk '{print $14, $15}' "/proc/$p/stat")
    tot_cpu=$((tot_cpu + ut + st))
    tot_rss=$((tot_rss + $(awk '/VmRSS/{print $2}' "/proc/$p/status" 2>/dev/null || echo 0)))
  done
  printf '%s %s %s %s %s\n' "$(date +%s.%N)" "$(awk "BEGIN{print $tot_cpu/$tck}")" "$tot_rss" \
    "$(du -sk ${OPERATOR_DATA} 2>/dev/null | awk '{s+=$1} END{print s+0}')" "$(cut -d' ' -f1 /proc/loadavg)"
}
operator_pids() {
  if [ -n "${OPERATOR_PIDS_CMD:-}" ]; then $OPERATOR_PIDS_CMD; else echo "${OPERATOR_PROCESSES:-}"; fi
}

scenario_load() {
  SCENARIO=load
  local users=${USERS:-100} par=${PAR:-8} amount=${AMOUNT:-200000} steps=${STEPS:-"1 2 4 8 16 32"} secs=${STEP_SECONDS:-60}
  USERS=$users; PAY=${PAY:-1000}
  mkdir -p "$RUN/load"
  local port=${PROXY_PORT:-$((20000 + RANDOM % 9000))}
  say "load: $users wallets, steps $steps of $secs s, through a timing proxy on 127.0.0.1:$port"
  python3 "$HERE/timing-proxy.py" "$port" "$OPERATOR_URL" "$RUN/load/proxy.log" &
  echo $! > "$RUN/load/proxy.pid"
  sleep 1
  local real_url=$OPERATOR_URL
  OPERATOR_URL=http://127.0.0.1:$port
  load_sample > "$RUN/load/samples"
  local t0 t_load; t0=$(date +%s); t_load=$t0
  # Wallets, in parallel.
  export -f arca mkwallet must try msg die say
  export ARCA RUN OPERATOR_URL OPERATOR_KEY NODE_URL NODE_USER NODE_PASSWORD_FILE EXIT_UNITS PATIENCE ASSET
  seq 0 $((users - 1)) | xargs -P "$par" -I{} bash -c 'mkwallet u{}'
  say "  $users wallets made in $(( $(date +%s) - t0 )) s"
  load_sample >> "$RUN/load/samples"
  # Funded in one round: one board, one distribution of a claim each.
  mkwallet funder
  board funder $((users * amount + 1000000))
  : > "$RUN/load/holders"
  for i in $(seq 0 $((users - 1))); do echo "$(arca "u$i" address | jq -r .key) $amount" >> "$RUN/load/holders"; done
  # One distribution's request must fit the operator's max_request_bytes
  # (64 KiB by default, about 300 holders): the holders go in chunks.
  split -l "${DIST_CHUNK:-250}" -d "$RUN/load/holders" "$RUN/load/holders."
  local f n=0
  for f in "$RUN"/load/holders.[0-9]*; do
    must funder distribute "$f" --asset "$ASSET" --shown 0 > "$f.json"
    n=$((n + 1))
  done
  for _ in $(seq 120); do
    produce; bury
    arca funder sync > /dev/null 2>&1 || true
    [ "$(arca funder distributions | jq '[.[]|select(.state=="released")]|length')" -ge "$n" ] && break
    sleep 2
  done
  say "  $n distributions of $users claims in all released"
  load_sample >> "$RUN/load/samples"
  t0=$(date +%s)
  seq 0 $((users - 1)) | xargs -P "$par" -I{} bash -c 'arca u{} claim > /dev/null || echo "claim u{} failed" >> "$RUN/log"'
  say "  $users claims taken up in $(( $(date +%s) - t0 )) s"
  load_sample >> "$RUN/load/samples"
  # Receive requests, made before the load, one a payment: each worker of
  # the largest step reads its own pool, so no two processes ever share a
  # wallet's directory while the load runs.
  local cmax; cmax=$(tr ' ' '\n' <<<"$steps" | sort -n | tail -1)
  local per=${REQUESTS:-10}
  for k in $(seq 0 $((cmax - 1))); do : > "$RUN/load/pool.$k"; rm -f "$RUN/load/pool.$k.used"; done
  # Worker k pays in every step of more than k at once: its pool is sized
  # by how many steps it pays in.
  local weights="" k c2
  for k in $(seq 0 $((cmax - 1))); do for c2 in $steps; do [ "$c2" -gt "$k" ] && weights="$weights $k"; done; done
  export WEIGHTS="$weights"
  export -f load_worker
  t0=$(date +%s)
  seq 0 $((users - 1)) | xargs -P "$par" -I{} bash -c '
    w=($WEIGHTS)
    for j in $(seq 1 '"$per"'); do
      k=${w[$(( ({} * '"$per"' + j) % ${#w[@]} ))]}
      for try in $(seq 20); do
        q=$(arca u{} receive --asset "$ASSET" | jq -r ".request // empty")
        [ -n "$q" ] && break; sleep 1
      done
      [ -n "$q" ] && echo "{} $q" >> "$RUN/load/pool.$k"
    done'
  for k in $(seq 0 $((cmax - 1))); do shuf -o "$RUN/load/pool.$k" "$RUN/load/pool.$k"; done
  say "  $((users * per)) receive requests made in $(( $(date +%s) - t0 )) s"
  # The chain moves on during the load, so rounds are made final.
  ( while :; do produce; bury; sleep "${TICK:-5}"; done ) > /dev/null 2>&1 &
  local ticker=$!
  ( while :; do load_sample >> "$RUN/load/samples"; sleep 5; done ) &
  local sampler=$!
  local c step=0
  export USERS PAY
  for c in $steps; do
    step=$((step + 1))
    local deadline=$(( $(date +%s) + secs ))
    echo "$step $c $(date +%s.%N)" >> "$RUN/load/steps"
    say "  step $step: $c at once for $secs s"
    local workers=()
    for k in $(seq 0 $((c - 1))); do load_worker "$k" "$c" "$deadline" "$step" & workers+=($!); done
    wait "${workers[@]}" 2>/dev/null || true
    echo "$step end $(date +%s.%N)" >> "$RUN/load/steps"
    load_report_step "$step" "$c"
    if [ -e "$RUN/load/stop" ]; then break; fi
  done
  kill "$ticker" "$sampler" 2>/dev/null || true
  load_sample >> "$RUN/load/samples"
  kill "$(cat "$RUN/load/proxy.pid")" 2>/dev/null || true
  OPERATOR_URL=$real_url
  load_rounds "$t_load" "$(date +%s)"
  load_report
}

# The operator's rounds during the run, from its log (OPERATOR_LOG_CMD
# prints it, each line led by its time: an epoch with milliseconds, or
# journalctl's short-iso-precise): when each went out, how many
# participations and vbytes it carried, and how long after its timer's
# tick it went out, the tick's phase taken from the quickest round.
load_rounds() {
  [ -n "${OPERATOR_LOG_CMD:-}" ] || return 0
  local interval
  interval=$(curl -fsS "$OPERATOR_URL/v1/info" | jq -r '.fills.round_interval_seconds // 0')
  $OPERATOR_LOG_CMD | python3 "$HERE/rounds.py" "$1" "$2" "$interval" > "$RUN/load/rounds.txt" || true
}

# One step's figures, and whether it is the first limit.
load_report_step() {
  python3 - "$RUN/load" "$1" "$2" <<'EOF' | tee -a "$RUN/log"
import glob, sys, json, statistics as st
d, step, c = sys.argv[1], sys.argv[2], int(sys.argv[3])
rows = []
for f in glob.glob(d + "/sends.*"):
    for l in open(f):
        p = l.split()
        if p[0] == step: rows.append(p)
steps = [l.split() for l in open(d + "/steps")]
t0 = float([s for s in steps if s[0] == step and s[1] != "end"][0][2])
t1 = float([s for s in steps if s[0] == step and s[1] == "end"][0][2])
ok = [r for r in rows if r[3] == "ok"]
err = [r for r in rows if r[3] != "ok"]
def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None
cos = []
for l in open(d + "/proxy.log"):
    p = l.split()
    if len(p) == 4 and "cosign_transfer" in p[1] and t0 <= float(p[0]) <= t1:
        cos.append((float(p[3]), p[2]))
codes = {}
for _, s in cos: codes[s] = codes.get(s, 0) + 1
reasons = {}
for r in err: reasons[r[4]] = reasons.get(r[4], 0) + 1
lat = [x for x, s in cos if s == "200"]
out = {"step": int(step), "at_once": c, "seconds": round(t1 - t0, 1), "sent": len(ok), "refused": len(err),
       "transfers_per_second": round(len(ok) / (t1 - t0), 2),
       "send_command_p50_s": pct([float(r[2]) for r in ok], .5), "send_command_p95_s": pct([float(r[2]) for r in ok], .95),
       "cosign_p50_ms": round(pct(lat, .5) * 1000, 1) if lat else None, "cosign_p95_ms": round(pct(lat, .95) * 1000, 1) if lat else None,
       "cosign_status": codes, "refusals": dict(sorted(reasons.items(), key=lambda x: -x[1])[:4])}
print("LOADSTEP " + json.dumps(out))
open(d + "/steps.json", "a").write(json.dumps(out) + "\n")
EOF
}

load_report() {
  python3 - "$RUN/load" "$USERS" "$RUN/b_arcad_log" <<'EOF' | tee -a "$RUN/log"
import json, sys, os
d, users = sys.argv[1], int(sys.argv[2])
steps = [json.loads(l) for l in open(d + "/steps.json")]
first = None
for prev, cur in zip(steps, steps[1:]):
    why = []
    if cur["refused"] > 0.02 * max(1, cur["sent"] + cur["refused"]): why.append("more than 2% refused")
    if cur["cosign_p95_ms"] and cur["cosign_p95_ms"] > 3000: why.append("co-signature p95 above 3 s")
    if cur["transfers_per_second"] < 1.2 * prev["transfers_per_second"]: why.append("throughput grew less than 20%% with %d at once" % cur["at_once"])
    if why:
        first = {"step": cur["step"], "at_once": cur["at_once"], "why": why, "best_transfers_per_second": max(s["transfers_per_second"] for s in steps)}
        break
samples = [l.split() for l in open(d + "/samples")]
def at(i): return {"cpu_s": float(samples[i][1]), "rss_kb": int(samples[i][2]), "disk_kb": int(samples[i][3])}
base, funded = at(0), at(3) if len(samples) > 3 else at(-1)
peak_rss = max(int(s[2]) for s in samples)
per_k = {"ram_mb_per_1000_users": round((funded["rss_kb"] - base["rss_kb"]) / 1024 * 1000 / users, 1),
         "disk_mb_per_1000_users": round((funded["disk_kb"] - base["disk_kb"]) / 1024 * 1000 / users, 1),
         "cpu_s_per_1000_users_funded": round((funded["cpu_s"] - base["cpu_s"]) * 1000 / users, 1),
         "peak_rss_mb": round(peak_rss / 1024, 1), "rss_mb_at_start": round(base["rss_kb"] / 1024, 1)}
# The operator's CPU, in cores kept busy, and memory over each step.
steps_cpu = []
marks = [l.split() for l in open(d + "/steps")]
for st in steps:
    t0 = float([m for m in marks if m[0] == str(st["step"]) and m[1] != "end"][0][2])
    t1 = float([m for m in marks if m[0] == str(st["step"]) and m[1] == "end"][0][2])
    inside = [s for s in samples if t0 <= float(s[0]) <= t1]
    if len(inside) >= 2:
        cpu = (float(inside[-1][1]) - float(inside[0][1])) / (float(inside[-1][0]) - float(inside[0][0]))
        steps_cpu.append({"step": st["step"], "operator_cores_busy": round(cpu, 2), "rss_mb": round(int(inside[-1][2]) / 1024, 1),
                          "machine_load": float(inside[-1][4])})
rounds = [json.loads(l) for l in open(d + "/rounds.txt")] if os.path.exists(d + "/rounds.txt") else []
print("LOADSUMMARY " + json.dumps({"users": users, "steps": steps, "first_limit": first, "footprint": per_k,
                                   "steps_cpu": steps_cpu, "rounds": rounds}))
EOF
}
