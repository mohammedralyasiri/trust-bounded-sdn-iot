#!/usr/bin/env bash
# SDN-IoT research lab setup for Ubuntu 22.04/24.04 (native, VM, or WSL2)
# Usage:  sudo bash setup.sh
set -e

echo "== 1) System packages: Mininet, Open vSwitch, traffic tools =="
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  mininet openvswitch-switch iproute2 iputils-ping hping3 tcpreplay \
  python3-pip python3-venv curl git

echo "== 2) Start Open vSwitch =="
/usr/share/openvswitch/scripts/ovs-ctl start --system-id=random || true

echo "== 3) Check whether the OVS kernel module is available =="
if modprobe openvswitch 2>/dev/null; then
  echo "KERNEL datapath available -> timing results are publishable."
  echo "datapath=kernel" > /etc/sdn-lab-datapath
else
  echo "WARNING: no OVS kernel module (common on WSL2)."
  echo "Falling back to userspace datapath -> use a VM or native Ubuntu for final latency measurements."
  echo "datapath=user" > /etc/sdn-lab-datapath
fi

echo "== 4) Python environment: controller + RL =="
python3 -m venv /opt/sdnlab
/opt/sdnlab/bin/pip install --upgrade pip
/opt/sdnlab/bin/pip install os-ken gymnasium stable-baselines3 torch pandas numpy scapy ollama

echo "== 5) Local LLM via Ollama =="
if ! command -v ollama >/dev/null; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
# 7-8B model needs ~8 GB RAM (or a GPU). Use qwen2.5:3b on weaker machines.
ollama pull qwen2.5:7b || ollama pull qwen2.5:3b

echo "== Done =="
echo "Activate env:   source /opt/sdnlab/bin/activate"
echo "Run the test:   sudo bash run_test.sh"
