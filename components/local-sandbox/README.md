# RAIccoon Malware Sandbox

RAIccoon Malware Sandbox is a local-first VirtualBox detonation lab for controlled Windows malware triage. It restores a clean Windows snapshot, starts host-only DNS/HTTP/HTTPS simulation, captures traffic, runs a sample through the Windows guest, stages run artifacts into REMnux for static and network analysis, collects Windows artifacts, parses behavior, and generates triage detections.

This repository is designed for defenders and researchers who want a reproducible sandbox without sending samples to public services.

## Capabilities

- VirtualBox snapshot restore and post-run cleanup
- Host-only DNS wildcarding with `dnsmasq`
- Fake HTTP on `80/8080` and HTTPS on `443`
- PCAP capture with `tshark`
- Per-run Suricata validation and capture
- Bundled custom Suricata rules for suspicious dynamic DNS, PowerShell downloaders, and tunnel/RMM TLS SNI patterns
- Host-side Suricata runs now inherit the bundled repo ruleset plus run-local `.pw` heuristics
- Windows guest collection for processes, services, tasks, WMI, autoruns, recent files, EVTX logs, and optional memory dumps
- Sysmon-oriented behavior parsing
- REMnux-offloaded static triage, PCAP parsing, bundled YARA rescanning, and report regeneration via VirtualBox Guest Control
- Auto-generated `summary.json`, `behavior_summary.json`, `analysis.md`, YARA, Sigma, and KQL detections
- Bundled reusable YARA triage rules for encoded PowerShell, LOLBIN droppers, and ransomware disruption strings
- Automatic bundled YARA triage over the staged sample and extracted guest artifacts during report generation / reparse
- `--parse-only` / `--report-only` mode for reprocessing completed runs

## Safety Model

Use a dedicated host-only VirtualBox network. Do not bridge the malware VM to your production network. Treat every run artifact as potentially malicious.

Recommended defaults:

- VM name: `win-malware-lab`
- Snapshot: `clean-guestadditions-sysmon`
- Host-only interface: `vboxnet0`
- Host bridge IP (host-only adapter): `192.168.56.254`
- REMnux analysis gateway / Windows default gateway + DNS: `192.168.56.1`
- Guest IP: `192.168.56.20`
- Sample archive credential: document out-of-band; do not commit it.

## Quick Start

```bash
git clone <your-repo-url> raiccoon-malware-sandbox
cd raiccoon-malware-sandbox
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m raiccoon_sandbox.local_vbox_detonate --help
```

Run a password-protected sample archive:

```bash
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate \
  /path/to/sample.7z \
  --password infected \
  --duration 180
```

Re-parse a completed run:

```bash
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate \
  --parse-only \
  --run-dir /path/to/runs/2026-06-02_110358_deadbeefcafe
```

Re-parse a completed run and force fresh static triage on the analysis side:

```bash
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate \
  --parse-only \
  --retriage \
  --run-dir /path/to/runs/2026-06-02_110358_deadbeefcafe
```

## Repository Layout

```text
src/raiccoon_sandbox/       Python runner and parser
scripts/                    Guest/host setup helpers
configs/                    Example local configuration
docs/                       Rebuild, operations, and safety docs
rules/                      Bundled Suricata and YARA rulesets
tests/                      Unit tests for parser and rule behavior
examples/                   Non-malicious example outputs/templates
```

## Bundled Rulesets

- Suricata: `rules/suricata/raiccoon-local.rules`
  - suspicious dynamic DNS providers often seen in opportunistic malware and throwaway C2
  - suspicious staging/C2 domains such as paste sites, Discord-hosted delivery, and transfer services
  - PowerShell downloader / encoded-command patterns in HTTP URIs
  - suspicious HTTP user-agents from common automation or bot tooling
  - TLS SNI hits for common tunnel or remote-management infrastructure
  - family-focused heuristics for stealer exfil, loader staging URIs, and ransomware leaksite/negotiation domains
- YARA: `rules/yara/raiccoon_static_triage.yar`
  - encoded PowerShell execution artifacts
  - LOLBIN downloader / script launcher strings
  - ransomware recovery-disruption command strings
  - remote-access / tunnel tooling artifacts
  - credential-access / LSASS-targeting artifacts
  - family-focused stealer, loader/stager, and ransom-note artifacts

Helper script:
- `scripts/run_yara_triage.sh <path>` recursively scans a sample directory or extracted artifact tree with the bundled YARA ruleset.

Pipeline integration:
- local host-side analysis now writes `yara_triage_summary.json` and `yara_triage_hits.txt` for both fresh runs and `--parse-only` / `--report-only` reparses
- REMnux-offloaded parse/report runs now stage the bundled YARA helper plus ruleset into the analysis share and regenerate the same `yara_triage_summary.json` / `yara_triage_hits.txt` outputs explicitly on the analysis side
- host-side Suricata now builds `suricata_local.rules` from the repo-bundled ruleset plus run-local heuristics before validation/start
- generated detections now include family-focused `sigma_yara_family.yml` and `kql_triage_hunts.kql` when bundled YARA triage hits are present

The REMnux setup helper now installs the custom Suricata ruleset into `/etc/suricata/rules/raiccoon-local.rules`, the bundled YARA triage rules into `/opt/raiccoon/rules/yara/raiccoon_static_triage.yar`, and the helper script into `/opt/raiccoon/scripts/run_yara_triage.sh`.

## Required Host Tools

- `VirtualBox` / `VBoxManage`
- `tshark` and `capinfos`
- `dnsmasq`
- `xorriso`
- `7z`
- `openssl`
- REMnux VM with Guest Additions / Guest Control support recommended as the analysis VM
- `suricata` recommended
- `python-evtx` optional for Sysmon EVTX parsing
- `zeek` optional for future protocol enrichment
- `volatility3` optional for memory analysis

## Legal and Ethical Use

Only analyze samples you are authorized to handle. Keep the VM isolated, use host-only networking, and never upload live malware or generated run artifacts to a public repository.
