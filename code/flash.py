#!/usr/bin/env python3
"""Benign flash crowd: a device legitimately contacts many destinations at once
(e.g. firmware/CDN fetch, service discovery). Own source IP, many new flows.
usage: flash.py RATE DURATION DST1 DST2 ..."""
import socket, sys, time
rate, dur, dsts = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3:]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end, i = time.time() + dur, 0
while time.time() < end:
    s.sendto(b"x" * 64, (dsts[i % len(dsts)], 5683 + (i // len(dsts)) % 100))   # CoAP-like port
    i += 1
    time.sleep(1.0 / rate)
