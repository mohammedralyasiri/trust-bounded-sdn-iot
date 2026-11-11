#!/usr/bin/env bash
# Experiment campaign. Usage: sudo bash campaign.sh test|quick|full|test3|phase3|test4|phase4|seeds10|onostest|onos|gpu|v10|v10s|scale
#  test4 : PPO v4 at full scale, 2 runs (~10 min)   phase4: PPO v4, 8 scenarios x 10 seeds (~6 h)
#  redo42: 45 runs of seeds10 that failed the host-health check (~3.5 h)
#  seeds10: 12 ppo4 re-runs + threshold seeds 1-10 (fixed) + seeds 6-10 for rule/meter/ppo (212 runs, ~16 h; resumable)
#  test3 : 5 short runs (~10 min) -> checks the rule and PPO defenses on this machine
#  onostest: 2 short runs with ONOS (~10 min)   onos: 8 scenarios x 5 seeds with ONOS (~4 h)
#  phase3: after "full" - adds rule + ppo defenses (8 scenarios x 5 seeds) and flash-crowd for all (~8 h)
#  quick : 24 devices, 80 s runs, 7 scenarios x 3 defenses x 1 seed  (~45 min)  -> sanity check
#  full  : 96 devices, 240 s runs (attack 120 s)
#          stage A: no defense, 7 scenarios x 10 seeds
#          stage B: threshold + meter, 7 scenarios x 5 seeds          (~12 h total)
# Re-running continues where it stopped (finished runs are skipped).
cd "$(dirname "$0")"
PROFILE=${1:-quick}
SCEN="benign flood lowslow burst mimicry correlated botnet flashcrowd"
if [ "$PROFILE" = "full" ]; then
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for s in $SCEN; do for k in 1 2 3 4 5 6 7 8 9 10; do PLAN="$PLAN none:$s:$k"; done; done
  for d in threshold meter; do for s in $SCEN; do for k in 1 2 3 4 5; do PLAN="$PLAN $d:$s:$k"; done; done; done
elif [ "$PROFILE" = "phase3" ]; then
  # continues results_full: adds the learned (ppo) and rule-based defenses, and the flash-crowd
  # false-positive scenario for every defense
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for d in rule ppo; do for s in $SCEN; do for k in 1 2 3 4 5; do PLAN="$PLAN $d:$s:$k"; done; done; done
  for k in 1 2 3 4 5 6 7 8 9 10; do PLAN="$PLAN none:flashcrowd:$k"; done
  for d in threshold meter; do for k in 1 2 3 4 5; do PLAN="$PLAN $d:flashcrowd:$k"; done; done
elif [ "$PROFILE" = "test4" ]; then
  # PPO v4 check at FULL scale (96 devices) - the small topology hid the v3 botnet failure
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN="ppo4:botnet:1 ppo4:flashcrowd:1"
elif [ "$PROFILE" = "phase4" ]; then
  # PPO v4 (+10 s hold): 8 scenarios x 10 seeds. Earlier ppo4 runs without the hold are kept aside.
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  if [ -d "$RES/ppo4" ] && [ ! -f "$RES/ppo4/.hold" ]; then mv "$RES/ppo4" "$RES/ppo4_nohold_$(date +%H%M)"; fi
  mkdir -p "$RES/ppo4"; touch "$RES/ppo4/.hold"
  PLAN=""
  for s in $SCEN; do for k in 1 2 3 4 5 6 7 8 9 10; do PLAN="$PLAN ppo4:$s:$k"; done; done
elif [ "$PROFILE" = "seeds10" ]; then
  # statistical power: 10 seeds for every defense. threshold is re-run from seed 1 because v4 fixed
  # its host-port test (v3 could block the broker port for ~20 s at start-up, before the attack window)
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  if [ -d "$RES/threshold" ] && [ ! -f "$RES/threshold/.v4" ]; then mv "$RES/threshold" "$RES/threshold_v3"; fi
  mkdir -p "$RES/threshold"; touch "$RES/threshold/.v4"
  # v4.1 re-runs, done first:
  #  (a) 12 ppo4 runs where a core-switch link was mistaken for a device port at start-up
  #      (fixed by MAC-home link detection; the other ppo4 runs never touched a link)
  #  (b) runs that fail the testbed health check: pre-attack MQTT p95 > 8 ms (normal ~4.5 ms), i.e. the
  #      host itself was slow before any attack or defense action (e.g. after the PC slept)
  REDO="ppo4:benign:4 ppo4:benign:5 ppo4:benign:7 ppo4:benign:10 ppo4:burst:8 ppo4:correlated:10
        ppo4:flashcrowd:8 ppo4:flashcrowd:10 ppo4:flood:4 ppo4:flood:5 ppo4:mimicry:5 ppo4:mimicry:9
        ppo4:burst:1 ppo4:burst:2 ppo4:burst:3 ppo4:burst:4 ppo4:burst:5 ppo4:burst:6 ppo4:burst:7
        ppo4:correlated:7 ppo4:correlated:8 ppo4:flashcrowd:9 ppo4:lowslow:4 ppo4:lowslow:6 ppo4:lowslow:7 ppo4:lowslow:8
        ppo4:lowslow:9 ppo4:lowslow:10 meter:botnet:4 none:botnet:1 none:lowslow:10 rule:benign:2"
  if [ ! -f "$RES/.redo41" ]; then
    mkdir -p "$RES/_replaced_v41"
    for x in $REDO; do IFS=: read D S K <<< "$x"
      if [ -d "$RES/$D/${S}_seed$K" ]; then mkdir -p "$RES/_replaced_v41/$D"; mv "$RES/$D/${S}_seed$K" "$RES/_replaced_v41/$D/"; fi
    done
    touch "$RES/.redo41"
  fi
  PLAN=""
  for x in $REDO; do PLAN="$PLAN $x"; done
  for s in $SCEN; do for k in 1 2 3 4 5 6 7 8 9 10; do PLAN="$PLAN threshold:$s:$k"; done; done
  for d in rule meter ppo; do for s in $SCEN; do for k in 6 7 8 9 10; do PLAN="$PLAN $d:$s:$k"; done; done; done
elif [ "$PROFILE" = "redo42" ]; then
  # runs of seeds10 that failed the host-health check (PC busy, slept or switched off): redone with the
  # automatic health retry. Runs where the controller stopped during the attack are kept (real outcome).
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  REDO="meter:flashcrowd:10 ppo:benign:10 ppo:benign:6 ppo:benign:7 ppo:benign:8 ppo:benign:9 ppo:botnet:10
        ppo:botnet:9 ppo:burst:10 ppo:burst:6 ppo:burst:7 ppo:burst:8 ppo:burst:9 ppo:correlated:10 ppo:correlated:6
        ppo:correlated:7 ppo:correlated:8 ppo:correlated:9 ppo:flood:10 ppo:flood:6 ppo:flood:7 ppo:flood:8
        ppo:flood:9 ppo:lowslow:10 ppo:lowslow:6 ppo:lowslow:7 ppo:lowslow:8 ppo:lowslow:9 ppo:mimicry:10
        ppo:mimicry:6 ppo:mimicry:7 ppo:mimicry:8 ppo:mimicry:9 ppo4:flashcrowd:9 ppo4:lowslow:5 rule:burst:10
        rule:burst:9 rule:correlated:9 rule:mimicry:10 rule:mimicry:6 threshold:benign:10 threshold:correlated:3
        threshold:correlated:4 threshold:correlated:5 threshold:flood:5"
  if [ ! -f "$RES/.redo42" ]; then
    for x in $REDO; do IFS=: read D S K <<< "$x"
      if [ -d "$RES/$D/${S}_seed$K" ]; then mkdir -p "$RES/_replaced_v42/$D"; mv "$RES/$D/${S}_seed$K" "$RES/_replaced_v42/$D/"; fi
    done
    touch "$RES/.redo42"
  fi
  PLAN=""
  for x in $REDO; do PLAN="$PLAN $x"; done
elif [ "$PROFILE" = "baselines" ]; then
  # phase 8: published-method baselines re-implemented in the same testbed - hybrid RF+GB port classifier after
  # Mahar et al. 2026 (rf) and the destination-entropy detector of Mousavi & St-Hilaire 2015 (entropy), 8 x 5,
  # plus PPO v4 and the rule governor on the flash crowd in the same machine state. No LLM loaded.
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5; do
    for s in benign flood lowslow burst mimicry correlated botnet flashcrowd; do PLAN="$PLAN rf:$s:$k entropy:$s:$k"; done
    PLAN="$PLAN ppo4:flashcrowd:$k gov_rule:flashcrowd:$k"
  done
elif [ "$PROFILE" = "baselines2" ]; then
  # phase 8b: the 2026 port-level LLM detector (Swileh & Zhang) with the local Qwen2.5 3B, 8 scenarios x 5 seeds
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5; do
    for s in benign flood lowslow burst mimicry correlated botnet flashcrowd; do PLAN="$PLAN llmport:$s:$k"; done
  done
elif [ "$PROFILE" = "gpu" ]; then
  # phase 9: the LLM on the Windows host GPU (GTX 1060 6 GB, Ollama, reached at 10.0.2.2) - the governor as a
  # separate box. Hybrid V7 with Qwen2.5 3B and 7B on free-text notices (flashfree, poisonfree) and the
  # structured flash crowd; the Swileh & Zhang port-level detector (3B) at GPU speed, 8 scenarios x 5 seeds.
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5; do
    PLAN="$PLAN gpu_hqwen3b_v7:flashfree:$k gpu_hqwen7b_v7:flashfree:$k gpu_hqwen3b_v7:poisonfree:$k gpu_hqwen7b_v7:poisonfree:$k"
    PLAN="$PLAN gpu_hqwen3b_v7:flashcrowd:$k"
    for s in benign flood lowslow burst mimicry correlated botnet flashcrowd; do PLAN="$PLAN gpu_llmport:$s:$k"; done
  done
  for k in 6 7 8 9 10; do PLAN="$PLAN gpu_hqwen3b_v7:flashfree:$k"; done
elif [ "$PROFILE" = "llmport2" ]; then
  # phase 9b: Swileh & Zhang (2026) re-run with their Fig. 2 prompt template, on the host GPU, Qwen2.5 7B (5 seeds)
  # and 3B (3 seeds). The v7.1 gpu_llmport runs (our first prompt wording: the 3B model flagged every port in every
  # round) are kept aside as gpu_llmport_v71.
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  [ -d "$RES/gpu_llmport" ] && [ ! -f "$RES/gpu_llmport/.v72" ] && mv "$RES/gpu_llmport" "$RES/gpu_llmport_v71"
  mkdir -p "$RES/gpu_llmport"; touch "$RES/gpu_llmport/.v72"
  PLAN=""
  for k in 1 2 3 4 5; do
    for s in benign flood lowslow burst mimicry correlated botnet flashcrowd; do PLAN="$PLAN gpu_llmport7b:$s:$k"; done
    if [ $k -le 3 ]; then for s in benign flood lowslow burst mimicry correlated botnet flashcrowd; do PLAN="$PLAN gpu_llmport:$s:$k"; done; fi
  done
elif [ "$PROFILE" = "free" ]; then
  # phase 7: free-text notices (English / Arabic, devices named by model or type only) resolved through the
  # asset inventory. flashfree: legitimate crowd; poisonfree: forged free-text notice naming the bots.
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5 6 7 8 9 10; do
    PLAN="$PLAN gov_rule:flashfree:$k gov_hqwen3b_v7:flashfree:$k"
    [ $k -le 5 ] && PLAN="$PLAN ppo4:flashfree:$k gov_rule:poisonfree:$k gov_hqwen3b_v7:poisonfree:$k"
  done
elif [ "$PROFILE" = "pox" ]; then
  # phase 6b: second lightweight reactive controller (POX l2_learning, no defense), 8 scenarios x 3 seeds,
  # a third matched os-ken no-defense seed (nonec) in the same VM state, and the V8 test: spoofed-source
  # traffic from other edge switches against an offloaded flash crowd, rule governor with / without V8
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3; do
    for s in benign flood lowslow burst mimicry correlated botnet flashcrowd; do PLAN="$PLAN pox:$s:$k"; done
  done
  for s in benign flood lowslow burst mimicry correlated botnet flashcrowd; do PLAN="$PLAN nonec:$s:3"; done
  for k in 1 2 3; do PLAN="$PLAN gov_rule:spoofoff:$k gov_rule_nov8:spoofoff:$k"; done
elif [ "$PROFILE" = "sens" ]; then
  # phase 6: sensitivity of the harm bound. Rule governor (deterministic, fooled by the forged notice in
  # poison) with fast-path cap OFF_PPS in {25..400} pkt/s and budget OFF_MAX in {10,20,35}% of device ports;
  # the benign flash crowd measures what each cap costs the legitimate fast path. No LLM loaded.
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4; do
    for c in 25 50 100 200 400; do PLAN="$PLAN sr_p${c}_m35:poison:$k"; done
    for m in 10 20; do PLAN="$PLAN sr_p100_m${m}:poison:$k"; done
  done
  for k in 1 2; do for c in 25 50 100 200 400; do PLAN="$PLAN sr_p${c}_m35:flashcrowd:$k"; done; done
elif [ "$PROFILE" = "v10" ]; then
  # V10 (reverse-path pinning): revflood without/with V10 (5 seeds), V10 regression on the trust scenarios (3 seeds)
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5; do PLAN="$PLAN gov_rule:revflood:$k gov_rule_v10:revflood:$k"; done
  for k in 1 2 3; do
    for s in flashcrowd poison inject spoofoff; do PLAN="$PLAN gov_rule_v10:$s:$k"; done
    PLAN="$PLAN gov_hqwen3b_v7v10:inject:$k"
  done
elif [ "$PROFILE" = "v10s" ]; then
  # V10 source-pinned variant (reply rules match the local /24): revflood (5 seeds; the unpinned gov_rule arm is in v10),
  # and the regression scenarios that strict V10 degraded (3 seeds)
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5; do PLAN="$PLAN gov_rule_v10s:revflood:$k"; done
  for k in 1 2 3; do
    for s in flashcrowd poison inject spoofoff; do PLAN="$PLAN gov_rule_v10s:$s:$k"; done
    PLAN="$PLAN gov_hqwen3b_v7v10s:inject:$k"
  done
elif [ "$PROFILE" = "v10b" ]; then
  # V10b = source-pinned reply rules with the local /24 taken from device ports only (v7.4's v10s took it from the
  # first learned port, which on some switches was the uplink). One extra run logs every PacketIn (diagnostic).
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN="gov_rule_v10bd:flashcrowd:1"
  for k in 1 2 3; do
    for s in flashcrowd poison inject spoofoff; do PLAN="$PLAN gov_rule_v10b:$s:$k"; done
    PLAN="$PLAN gov_hqwen3b_v7v10b:inject:$k"
  done
  for k in 1 2 3 4 5; do PLAN="$PLAN gov_rule_v10b:revflood:$k"; done
elif [ "$PROFILE" = "final" ]; then
  # v7.6 = V10b with fixed rule priorities (forward 12 > reply 11 > reactive 10) and M scaled with the network.
  # (1) reply path: random-source flood (revflood) and own-address flood (revown), 5 seeds; (2) regression, 3 seeds;
  # (3) scaling at 96 and 192 devices with the scaled M, 3 seeds
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5; do PLAN="$PLAN gov_rule_v10c:revflood:$k gov_rule:revown:$k gov_rule_v10c:revown:$k"; done
  for k in 1 2 3; do
    for s in flashcrowd poison inject spoofoff; do PLAN="$PLAN gov_rule_v10c:$s:$k"; done
    PLAN="$PLAN gov_hqwen3b_v7v10c:inject:$k"
  done
  for k in 1 2 3; do for e in 8 16; do for s in flashcrowd botnet; do PLAN="$PLAN gov_rule_v10c_e$e:$s:$k"; done; done; done
elif [ "$PROFILE" = "scale" ]; then
  # scaling: 96, 192 and 384 devices (8, 16 and 32 edge switches x 12; 96 re-run with the CPU/RSS sampler), flash crowd and botnet, PPO v4 alone and
  # with the rule governor (+V10), 3 seeds; the pre-attack MQTT health bound is relaxed to 50 ms at this size
  export HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3; do for e in 8 16 32; do for s in flashcrowd botnet; do
    PLAN="$PLAN ppo4_e$e:$s:$k gov_rule_v10b_e$e:$s:$k"
  done; done; done
elif [ "$PROFILE" = "phase5b" ]; then
  # phase 5b: hybrid governor with evidence-gated revocation (V7), same attacks and seeds as phase 5,
  # plus V7 on the benign flash crowd (it must not cost the legitimate fast path anything)
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5 6 7 8 9 10; do PLAN="$PLAN gov_hqwen3b_v7:inject:$k gov_hqwen3b_v7:poison:$k"; done
  for k in 1 2 3 4 5; do PLAN="$PLAN gov_hqwen3b_v7:flashcrowd:$k"; done
elif [ "$PROFILE" = "phase5" ]; then
  # phase 5: poisoned operations feed (forged OTA notice; forged notice + prompt injection),
  # PPO alone vs rule / hybrid governor, each with and without the verifier bounds; 10 seeds
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5 6 7 8 9 10; do
    for s in inject poison; do
      for d in gov_hqwen3b gov_hqwen3b_nb gov_rule gov_rule_nb ppo4; do PLAN="$PLAN $d:$s:$k"; done
    done
  done
elif [ "$PROFILE" = "ctrl" ]; then
  # environment control: PPO v4 alone re-run now, in the same VM state as the phase-4 campaign
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5; do for s in mimicry benign flashcrowd; do PLAN="$PLAN ppo4c:$s:$k"; done; done
elif [ "$PROFILE" = "phase4c" ]; then
  # phase 4 main campaign: rule governor vs hybrid governor (rule provisional + qwen2.5:3b review),
  # 8 scenarios x 10 seeds, seed-major; then the LLM-only governor as an ablation (3 scenarios x 5 seeds)
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5 6 7 8 9 10; do
    for s in flashcrowd botnet benign flood lowslow burst mimicry correlated; do
      PLAN="$PLAN gov_hqwen3b:$s:$k gov_rule:$s:$k"
    done
  done
  for k in 1 2 3 4 5; do for s in flashcrowd botnet benign; do PLAN="$PLAN gov_qwen3b:$s:$k"; done; done
elif [ "$PROFILE" = "phase4b" ]; then
  # phase 4 main campaign: PPO v4 + governance, rule-based vs LLM (qwen2.5:3b) governor, 8 scenarios x 10 seeds;
  # seed-major order so that every few hours a complete set of scenarios exists
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  for k in 1 2 3 4 5 6 7 8 9 10; do
    for s in flashcrowd botnet benign flood lowslow burst mimicry correlated; do
      PLAN="$PLAN gov_qwen3b:$s:$k gov_rule:$s:$k"
    done
  done
elif [ "$PROFILE" = "govtest" ]; then
  # phase 4 check at full scale: rule-based governor and the LLM governor (needs llmbench first)
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN="gov_rule:flashcrowd:1 gov_qwen3b:flashcrowd:1 gov_qwen7b:flashcrowd:1 gov_qwen3b:botnet:1"
elif [ "$PROFILE" = "onos" ]; then
  # cross-controller validation: same testbed and scenarios, ONOS instead of os-ken (no defense)
  export EDGES=8 HOSTS=12 A0=60 A1=180 DUR=240; RES=results_full
  PLAN=""
  # seed-major; os-ken without defense (nonec) re-run alongside for seeds 1-2 as the matched control
  for k in 1 2 3 4 5; do for s in $SCEN; do
    PLAN="$PLAN onos:$s:$k"; [ $k -le 2 ] && PLAN="$PLAN nonec:$s:$k"
  done; done
elif [ "$PROFILE" = "onostest" ]; then
  export EDGES=4 HOSTS=6 A0=20 A1=60 DUR=80; RES=results_onostest
  PLAN="onos:benign:1 onos:flood:1"
elif [ "$PROFILE" = "test3" ]; then
  export EDGES=4 HOSTS=6 A0=20 A1=60 DUR=80; RES=results_test3
  PLAN="ppo:benign:1 ppo:flood:1 ppo:botnet:1 rule:flashcrowd:1 ppo:flashcrowd:1"
elif [ "$PROFILE" = "test" ]; then
  export EDGES=4 HOSTS=6 A0=20 A1=60 DUR=80; RES=results_test
  PLAN="none:benign:1 threshold:flood:1"
else
  export EDGES=4 HOSTS=6 A0=20 A1=60 DUR=80; RES=results_quick
  PLAN=""
  for d in none threshold meter; do for s in $SCEN; do PLAN="$PLAN $d:$s:1"; done; done
fi
TOTAL=$(echo $PLAN | wc -w); N=0; START=$(date +%s)
if [ -d results ] && [ ! -L results ]; then mv results "results_v1_$(date +%Y%m%d_%H%M)"; fi
case "$PROFILE" in test|test3|onostest) rm -rf "$RES";; esac
rm -f results; mkdir -p "$RES"; ln -sfn "$RES" results
for item in $PLAN; do
  N=$((N + 1)); IFS=: read D S K <<< "$item"
  # done = the run produced its data (a run whose testbed never started leaves events.meta alone: redo it)
  if [ -f "results/$D/${S}_seed${K}/events.meta" ] && [ -f "results/$D/${S}_seed${K}/events.csv" ]; then continue; fi
  ELAPSED=$(( ($(date +%s) - START) / 60 ))
  echo "[$N/$TOTAL] defense=$D scenario=$S seed=$K   (elapsed ${ELAPSED} min)"
  # up to 3 attempts: a run is redone if the host itself was slow/paused before the attack (health.py)
  for TRY in 1 2 3; do
    bash run_experiment.sh "$S" "$K" "$D" > "results/.run.log" 2>&1 || echo "   run failed (continuing)"
    cp results/.run.log "results/$D/${S}_seed${K}/console.log" 2>/dev/null
    # the pre-attack MQTT bound reflects the controller's own steady state: POX (OpenFlow 1.0, flows that
    # idle out after 10 s and are re-learned) sits at ~9 ms where os-ken sits at ~4.5 ms, so it gets 15 ms
    HM=8; [ "$D" = "pox" ] && HM=15
    case "$D" in *_e[0-9]*) HM=50;; esac
    if SDN_HEALTH_MQTT_MS=$HM ${SDN_PY:-/opt/sdnlab/bin/python} health.py "results/$D/${S}_seed${K}"; then break; fi
    if [ $TRY -lt 3 ]; then
      rm -f "results/$D/${S}_seed${K}/events.meta"; echo "   retry $((TRY + 1))/3 after 60 s"; sleep 60
    fi
  done
  ${SDN_PY:-/opt/sdnlab/bin/python} brief.py "results/$D/${S}_seed${K}" || true
done
${SDN_PY:-/opt/sdnlab/bin/python} summarize.py --compare results | tee "results/compare.txt"
echo "CAMPAIGN $PROFILE DONE in $(( ($(date +%s) - START) / 60 )) min"
