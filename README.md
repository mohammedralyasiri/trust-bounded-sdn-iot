# Trust-Bounded Governance for LLM-Assisted SDN-IoT Defense — code and data

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24140059.svg)](https://doi.org/10.5281/zenodo.24140059)

Reproducibility package for:

> Jasim, M. R. (2026). *Trust-Bounded Governance for LLM-Assisted SDN-IoT Defense:
> Formal Safety Guarantees in the Presence of Prompt Injection.* Manuscript submitted to *Computer Networks*.
>
> Code and data: https://doi.org/10.5281/zenodo.24140059

## Contents

| Folder | What it holds |
| --- | --- |
| `code/` | os-ken controller extensions (`telemetry_switch.py`, `governance.py` = verifier V1–V10 and two-table fast path), governor (`governor.py`: rule, LLM, hybrid; asset-inventory selectors), Mininet topology and scenarios (`iot_topo.py`), run and campaign scripts, ONOS and POX launchers, summariser and health check |
| `code/baselines/` | Re-implemented published defenses for Section 7.8: `train_rf.py` and `rf_model.npz` (random forest + gradient boosting, after Mahar et al., 2026), `llmport.py` (port-level zero-training LLM detector after Swileh and Zhang, 2026, with their prompt template) and its self-test set; the entropy detector (Mousavi and St-Hilaire, 2015) is `DEFENSE=entropy` in `telemetry_switch.py` |
| `code/ppo/` | PPO trainer and simulator (`ppo_np.py`, `ppo_train.py`, `sim_env.py`), the two policies used in the paper (`ppo_policy_v3.npz`, `ppo_policy_v4.npz`) and their training logs |
| `installer/lab_v76.sh` | Self-contained installer: writes every code file, embeds POX 0.7.0 (Apache-2.0), and runs a named campaign |
| `analysis/` | `stats.py` (means and 95% t-intervals), `tests.py` (Mann–Whitney U, rank-biserial r, Holm), `meters.py` (fast-path rates from OpenFlow meter counters), `tests_baselines.py` (Section 7.8 tests), `freetext.py` (review latency, selectors and first offload in the free-text runs), `power.py` (sensitivity analysis of the Mann–Whitney tests), `reply_path.py`, `v10.py` and `v10_meters.py` (V10 tests, Section 7.5), `scale.py` and `bench_gov.py` (scaling study and governance microbenchmark, Section 7.9) |
| `data/summary_all.csv` | One row per run and phase (pre-attack, attack, recovery) for all 1,362 executed runs |
| `data/sensitivity_meters.csv` | Measured fast-path rate per run for the sensitivity sweep and the free-text forgery runs |
| `data/reply_path_runs.csv` | Per-run reply-path measurements for revflood and revown (Section 7.5) |
| `data/scale_runs.csv`, `data/bench_gov.csv` | Scaling runs with controller CPU and memory, and the governance microbenchmark (Section 7.9) |

Raw per-run logs (flow tables, PacketIn counters, governor prompts and answers, meter samples, join and MQTT
records; about 1 GB) are available from the author on request.

## Environment used in the paper

Ubuntu VM (VirtualBox), 8 vCPUs, 14 GB RAM, Intel i7-7700HQ host; Mininet with the Open vSwitch kernel
datapath (OpenFlow 1.3); os-ken; ONOS 2.7.0 (Docker); POX 0.7.0; Ollama with Qwen2.5 3B on CPU inside the VM, and, for the GPU runs, Ollama on the Windows host (NVIDIA GTX 1060, 6 GB) with Qwen2.5 3B and 7B, reached from the VM at `http://10.0.2.2:11434`.

## Running

```
sudo bash installer/lab_v76.sh <profile>
```

| Profile | Paper section | Runs |
| --- | --- | --- |
| `seeds10`, `phase4c`, `ctrl` | 7.1–7.2 | defenses × 8 scenarios × 10 seeds; governor ablations; LLM-resident control |
| `phase5`, `phase5b` | 7.3 | poison and inject, with and without the bound and V7 |
| `sens` | 7.4 | meter cap c ∈ {25, 50, 100, 200, 400}, budget φ ∈ {0.10, 0.20, 0.35} |
| `pox` | 7.5, 7.6 | POX baseline; V8 spoofing test |
| `onos` | 7.6 | ONOS baseline |
| `free` | 7.7 | free-text notices (English, Arabic) resolved through the asset inventory |
| `gpu` | 7.7 | free-text and templated notices with Qwen2.5 3B and 7B on the host GPU (Ollama on the host must be running with both models) |
| `baselines` | 7.8 | random forest + boosted trees and entropy detectors, 8 scenarios × 5 seeds |
| `llmport2` | 7.8 | Swileh and Zhang LLM detector on the host GPU, Qwen2.5 7B × 5 seeds and 3B × 3 seeds |
| `v10`, `v10s`, `v10b` | 7.5 | development versions of V10 (strict; source-pinned with the uplink bug; source-pinned) |
| `final` | 7.5, 7.9 | final V10 (`gov_rule_v10c`): revflood and revown, regression, scaling with M = max(40, ⌊φ\|P\|⌋) |
| `scale` | 7.9 | 96, 192 and 384 devices with PPO alone and with governance at M = 40 |

Each run leaves its logs in `~/sdn-iot-lab/results/<defense>/<scenario>_seed<k>/`; `summarize.py` builds
`summary_all.csv`. Runs whose pre-attack MQTT p95 exceeded 8 ms (15 ms for POX) or whose telemetry paused were
repeated automatically (up to three attempts). Eleven runs were excluded from the statistics: seven with a degraded host (listed in `analysis/stats.py`), three runs of a first LLM-detector prompt wording (`gpu_llmport_v71`) that failed the health check three times, and the 7B botnet seed-1 run of `llmport2`, during which the host was suspended.

## Licence

Code: MIT (see `LICENSE`). POX, ONOS and os-ken are third-party software under the Apache License 2.0.
