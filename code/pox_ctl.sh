#!/usr/bin/env bash
# POX 0.7.0 (gar) controller for the cross-controller comparison: forwarding.l2_learning, OpenFlow 1.0,
# reactive exact-match flows (ofp_match.from_packet, idle 10 s / hard 30 s), no defense.
# usage: pox_ctl.sh start LOG | stop
POX=/opt/pox
case "$1" in
  start)
    [ -f "$POX/pox.py" ] || { echo "POX missing in $POX"; exit 1; }
    LOG=$(readlink -f "$2")                 # the log path is relative to the lab; resolve it before cd
    cd "$POX" && nohup python3 pox.py log.level --INFO openflow.of_01 --port=6653 forwarding.l2_learning \
      > "$LOG" 2>&1 &
    for _ in $(seq 1 40); do ss -ltn | grep -q ':6653 ' && { echo "POX ready"; exit 0; }; sleep 0.5; done
    echo "POX did not open port 6653"; tail -5 "$LOG"; exit 1 ;;
  stop)
    pkill -f 'pox.py log.level' 2>/dev/null; sleep 1 ;;
esac
