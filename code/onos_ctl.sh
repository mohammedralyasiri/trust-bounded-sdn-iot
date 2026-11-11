#!/usr/bin/env bash
# Start (or restart) a clean ONOS 2.7 controller in Docker and configure reactive forwarding
# so it behaves like the os-ken baseline: per-IPv4-pair flow rules, 10 s idle timeout.
# usage: sudo bash onos_ctl.sh start|stop
IMG=onosproject/onos:2.7.0
REST=http://127.0.0.1:8181/onos/v1
A="-u onos:rocks"
case "$1" in
stop)
  docker rm -f onos >/dev/null 2>&1; exit 0 ;;
start)
  docker rm -f onos >/dev/null 2>&1
  docker run -d --name onos --network host \
    -e ONOS_APPS="drivers,openflow,hostprovider,lldpprovider,proxyarp,fwd" -e JAVA_OPTS="-Xms1g -Xmx3g" $IMG >/dev/null || exit 1
  echo -n "waiting for ONOS"
  for i in $(seq 1 120); do
    if curl -s $A "$REST/applications/org.onosproject.fwd" | grep -q '"state":"ACTIVE"'; then break; fi
    echo -n "."; sleep 2
  done
  echo
  curl -s $A "$REST/applications/org.onosproject.fwd" | grep -q '"state":"ACTIVE"' \
    || { echo "!!! ONOS did not become ready"; docker logs --tail 20 onos; exit 1; }
  for app in org.onosproject.openflow org.onosproject.hostprovider org.onosproject.lldpprovider org.onosproject.proxyarp org.onosproject.fwd; do
    curl -s $A -X POST "$REST/applications/$app/active" >/dev/null
  done
  curl -s $A -X POST -H "Content-Type: application/json" \
    -d '{"matchIpv4Address":"true","flowTimeout":"10","packetOutOnly":"false"}' \
    "$REST/configuration/org.onosproject.fwd.ReactiveForwarding" >/dev/null
  curl -s $A "$REST/configuration/org.onosproject.fwd.ReactiveForwarding" \
    | grep -o '"matchIpv4Address":{[^}]*}' | head -1
  # the OpenFlow listener comes up some seconds after the apps report ACTIVE
  echo -n "waiting for the OpenFlow port 6653"
  for i in $(seq 1 90); do ss -ltn | grep -q ':6653 ' && break; echo -n "."; sleep 2; done
  echo
  ss -ltn | grep -q ':6653 ' || { echo "!!! ONOS is not listening on 6653"; ss -ltnp | grep -i java; docker logs --tail 30 onos; exit 1; }
  echo "ONOS ready"
  ;;
*) echo "usage: $0 start|stop"; exit 1 ;;
esac
