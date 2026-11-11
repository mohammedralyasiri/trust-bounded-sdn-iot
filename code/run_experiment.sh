#!/usr/bin/env bash
# One run: controller (with chosen defense) + IoT testbed + summary.
# Usage: sudo bash run_experiment.sh <scenario> <seed> [defense]
#   scenario: benign flood lowslow burst mimicry correlated botnet flashcrowd | poison inject (phase 5)
#   defense : none threshold meter rule ppo ppo4 | gov_rule gov_qwen3b gov_qwen7b gov_llama8b gov_qwen7b_nb gov_qwen3b_nb gov_hqwen3b gov_hqwen7b gov_hqwen3b_nb gov_rule_nb gov_hqwen3b_v7 | onos (ONOS 2.7 reactive forwarding, no defense) | pox (POX l2_learning, no defense) | gov_rule_nov8 (V8 ablation) | gov_rule_v10 gov_hqwen3b_v7v10 (V10 reverse-path pinning) | rf (RF+GB, Mahar et al. 2026) | entropy (Mousavi & St-Hilaire 2015) | llmport (Swileh & Zhang 2026) | gpu_hqwen3b_v7 gpu_hqwen7b_v7 gpu_llmport gpu_llmport7b (LLM on the host GPU)
# Size/timing from env (defaults = full profile): EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240
# A run whose switches never reached the controller is retried once (it would measure nothing).
cd "$(dirname "$0")"
SC=${1:-benign}; SEED=${2:-1}; DEF=${3:-none}
EDGES=${EDGES:-8}; HOSTS=${HOSTS:-12}; A0=${A0:-60}; A1=${A1:-180}; DUR=${DUR:-240}
# scaling study: a defense name ending in _e<N> runs that defense on N edge switches (N x HOSTS devices)
RUNNAME=$DEF
case "$DEF" in *_e[0-9]*) EDGES=${DEF##*_e}; DEF=${DEF%_e*};; esac
OUT=results/$RUNNAME/${SC}_seed${SEED}
PY=${SDN_PY:-/opt/sdnlab/bin/python}
# LLM server: the VM's own Ollama (CPU) by default; gpu_* defenses use Ollama on the Windows host GPU
# (VirtualBox NAT address 10.0.2.2), i.e. the governor as a separate box
OLLAMA_URL=${OLLAMA_URL:-http://127.0.0.1:11434}
case "$DEF" in gpu_*) OLLAMA_URL=${GPU_OLLAMA_URL:-http://10.0.2.2:11434};; esac
export OLLAMA_URL

cleanup() {
  pkill -f 'run_ct[l].py' 2>/dev/null; pkill -f 'pox.py log.level' 2>/dev/null; pkill -f 'pox_pol[l].py' 2>/dev/null; pkill -x hping3 2>/dev/null; pkill -x mosquitto 2>/dev/null
  mn -c >/dev/null 2>&1
}

for ATTEMPT in 1 2; do
  cleanup
  rm -rf "$OUT"; mkdir -p "$OUT"
  if [ "$DEF" = "onos" ]; then
    # cross-controller validation: ONOS reactive forwarding, no defense
    bash onos_ctl.sh start > "$OUT/onos_start.log" 2>&1 || { cat "$OUT/onos_start.log"; continue; }
    echo "ts,dpid,port,action,reason" > "$OUT/actions.csv"
    $PY onos_poll.py "$OUT/metrics_ctl.csv" "$OUT/ctl.log" > /dev/null 2>&1 &
  elif [ "$DEF" = "pox" ]; then
    # cross-controller comparison: POX l2_learning (lightweight reactive, OpenFlow 1.0), no defense
    bash pox_ctl.sh start "$OUT/pox.log" > "$OUT/pox_start.log" 2>&1 || { cat "$OUT/pox_start.log"; continue; }
    echo "ts,dpid,port,action,reason" > "$OUT/actions.csv"
    echo "controller=pox" > "$OUT/ctl.log"
    $PY pox_poll.py "$OUT/metrics_ctl.csv" $((EDGES + 1)) > /dev/null 2>&1 &
  else
    # ppo = policy v3 (first calibration); ppo4 = policy v4 (simulator recalibrated on 96-device data)
    # ppo4 also uses a 10 s hold against allow/limit flapping; ppo (v3) keeps its original behaviour
    CDEF=$DEF; POL=ppo/ppo_policy.npz; HOLD=0
    # nonec = no defense on os-ken, re-run as the matched control of the ONOS runs (same VM state)
    if [ "$DEF" = "nonec" ]; then CDEF=none; fi
    case "$DEF" in gpu_llmport*) CDEF=llmport;; esac
    if [ "$DEF" = "ppo4" ] || [ "$DEF" = "ppo4c" ]; then CDEF=ppo; POL=ppo/ppo_policy_v4.npz; HOLD=10; fi
    # ppo4c = ppo4 re-run as an environment control, with the LLM loaded in memory as in the phase-4 runs
    if [ "$DEF" = "ppo4c" ]; then
      curl -s -m 300 $OLLAMA_URL/api/generate -d '{"model":"qwen2.5:3b","prompt":"ok","keep_alive":"30m","options":{"num_predict":1}}' > /dev/null || true
    fi
    # phase 4: PPO v4 + trust-bounded governance; the governor backend is chosen by the defense name
    GOV=0; GB=""; BOUND=1; V7=0; V8=1; V10=0; OPPS=100; OMAX=0.35
    case "$DEF" in
      # sensitivity sweep: rule governor with fast-path cap OPPS pkt/s and budget OMAX % of device ports
      sr_p*_m*)      GB=rulegov; OPPS=$(echo "$DEF" | sed 's/^sr_p\([0-9]*\)_m.*/\1/')
                     OMAX=$(echo "$DEF" | sed 's/.*_m\([0-9]*\)$/\1/' | awk '{printf "%.2f", $1/100}') ;;
      gov_rule)      GB=rulegov ;;
      gov_rule_nb)   GB=rulegov; BOUND=0 ;;
      gov_rule_nov8) GB=rulegov; V8=0 ;;
      gov_rule_v10)  GB=rulegov; V10=1 ;;
      gov_rule_v10s) GB=rulegov; V10=src ;;
      gov_rule_v10b) GB=rulegov; V10=src ;;
      gov_rule_v10c) GB=rulegov; V10=src; export SDN_GOV_MAX_DIR_SCALE=1 ;;
      gov_hqwen3b_v7v10c) GB=hybrid:ollama:qwen2.5:3b; V7=1; V10=src; export SDN_GOV_MAX_DIR_SCALE=1 ;;
      gov_rule_v10bd) GB=rulegov; V10=src; export SDN_DEBUG_PIN=1 ;;
      gov_hqwen3b_v7v10b) GB=hybrid:ollama:qwen2.5:3b; V7=1; V10=src ;;
      gov_hqwen3b_v7v10s) GB=hybrid:ollama:qwen2.5:3b; V7=1; V10=src ;;
      gov_rule_v10p) GB=rulegov; V10=pin ;;
      gov_hqwen3b_v7v10p) GB=hybrid:ollama:qwen2.5:3b; V7=1; V10=pin ;;
      gov_hqwen3b_v7v10) GB=hybrid:ollama:qwen2.5:3b; V7=1; V10=1 ;;
      gov_qwen3b)    GB=ollama:qwen2.5:3b ;;
      gov_qwen7b)    GB=ollama:qwen2.5:7b ;;
      gov_llama8b)   GB=ollama:llama3.1:8b ;;
      gov_qwen7b_nb) GB=ollama:qwen2.5:7b; BOUND=0 ;;
      gov_qwen3b_nb) GB=ollama:qwen2.5:3b; BOUND=0 ;;
      gov_hqwen3b)   GB=hybrid:ollama:qwen2.5:3b ;;
      gov_hqwen3b_v7) GB=hybrid:ollama:qwen2.5:3b; V7=1 ;;
      gov_hqwen7b)   GB=hybrid:ollama:qwen2.5:7b ;;
      gov_hqwen3b_nb) GB=hybrid:ollama:qwen2.5:3b; BOUND=0 ;;
      gpu_hqwen3b_v7) GB=hybrid:ollama:qwen2.5:3b; V7=1 ;;
      gpu_hqwen7b_v7) GB=hybrid:ollama:qwen2.5:7b; V7=1 ;;
    esac
    if [ -n "$GB" ]; then CDEF=ppo; POL=ppo/ppo_policy_v4.npz; HOLD=10; GOV=1; fi
    SDN_DEFENSE=$CDEF SDN_PPO_POLICY=$(pwd)/$POL SDN_PPO_HOLD_S=$HOLD SDN_METRICS=$OUT/metrics_ctl.csv SDN_ACTIONS=$OUT/actions.csv \
      SDN_GOV=$GOV SDN_GOV_DIR=$OUT SDN_GOV_BOUNDED=$BOUND SDN_GOV_V7=$V7 SDN_GOV_V8=$V8 SDN_GOV_V10=$V10 SDN_GOV_OFF_PPS=$OPPS SDN_GOV_OFF_MAX=$OMAX \
      PYTHONPATH=. $PY run_ctl.py telemetry_switch > "$OUT/ctl.log" 2>&1 &
  fi
  CTL=$!
  GPID=""
  if [ -n "$GB" ]; then
    # LLM backends: load the model into memory before the run (a cold load takes 40-120 s on CPU)
    case "$GB" in *ollama:*)
      curl -s -m 300 $OLLAMA_URL/api/generate -d "{\"model\":\"${GB##*ollama:}\",\"prompt\":\"ok\",\"keep_alive\":\"30m\",\"options\":{\"num_predict\":1}}" > /dev/null || true ;;
    esac
    GOV_BACKEND=$GB $PY governor.py "$OUT" > "$OUT/governor.log" 2>&1 & GPID=$!
  fi
  if [ "$CDEF" = "llmport" ]; then
    # Swileh & Zhang (2026) port-level LLM detector, same local model as our governor (gpu_llmport7b: 7B)
    LM=qwen2.5:3b; [ "$DEF" = "gpu_llmport7b" ] && LM=qwen2.5:7b; export LLMPORT_MODEL=$LM
    curl -s -m 300 $OLLAMA_URL/api/generate -d "{\"model\":\"$LM\",\"prompt\":\"ok\",\"keep_alive\":\"30m\",\"options\":{\"num_predict\":1}}" > /dev/null || true
    $PY baselines/llmport.py "$OUT" > "$OUT/llmport.log" 2>&1 & GPID=$!
  fi
  for _ in $(seq 1 30); do ss -ltn | grep -q ':6653 ' && break; sleep 0.5; done
  sleep 2
  # controller CPU (jiffies, utime+stime) and resident memory every 5 s, for the scaling study
  RPID=""
  CPID=$(pgrep -f 'run_ctl.py telemetry_switch' | head -1)
  if [ -n "$CPID" ]; then
    ( echo "ts,cpu_jiffies,rss_kb,hz"; HZ=$(getconf CLK_TCK)
      while [ -r /proc/$CPID/stat ]; do
        J=$(awk '{print $14+$15}' /proc/$CPID/stat 2>/dev/null); R=$(awk '/VmRSS/{print $2}' /proc/$CPID/status 2>/dev/null)
        echo "$(date +%s.%N),$J,$R,$HZ"; sleep 5; done ) > "$OUT/ctl_res.csv" 2>/dev/null & RPID=$!
  fi
  SETTLE=0; [ "$DEF" = "onos" ] && SETTLE=15
  # fast-path meters (offloaded devices): sample OpenFlow meter counters every 5 s on every edge switch,
  # to measure how much traffic actually passed each cap (empirical check of the harm bound)
  MPID=""
  if [ -n "$GB" ]; then
    ( echo "# OFF_PPS=$OPPS OFF_MAX=$OMAX"
      while true; do T=$(date +%s.%N)
        for i in $(seq 1 "$EDGES"); do ovs-ofctl -O OpenFlow13 meter-stats "s$i" 2>/dev/null | sed "s|^|$T s$i |"; done
        sleep 5; done ) > "$OUT/meters.log" 2>/dev/null & MPID=$!
  fi
  OFP=OpenFlow13; [ "$DEF" = "pox" ] && OFP=OpenFlow10
  OF_PROTO=$OFP TOPO_SETTLE=$SETTLE /usr/bin/python3 iot_topo.py --scenario "$SC" --seed "$SEED" --out "$OUT" \
    --edges "$EDGES" --hosts "$HOSTS" --attack-start "$A0" --attack-end "$A1" --duration "$DUR"
  kill $CTL $GPID $MPID $RPID 2>/dev/null; sleep 1; cleanup
  [ "$DEF" = "onos" ] && bash onos_ctl.sh stop
  if [ "$DEF" = "pox" ]; then
    grep "\] connected" "$OUT/pox.log" | sed 's/^/switch connected /' >> "$OUT/ctl.log"
    pkill -f 'pox_pol[l].py'; bash pox_ctl.sh stop
  fi
  if grep -q "switch connected" "$OUT/ctl.log"; then break; fi
  echo "!!! switches never connected to the controller (attempt $ATTEMPT)"
done
echo "defense=$RUNNAME" >> "$OUT/events.meta"
echo "edges=$EDGES" >> "$OUT/events.meta"
echo "ollama_url=$OLLAMA_URL" >> "$OUT/events.meta"
$PY summarize.py "$OUT"
