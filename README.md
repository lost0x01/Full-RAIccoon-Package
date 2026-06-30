# Full RAIccoon Package

A brand-neutral, local-first deployment skeleton for analyst teams that want a working starting point for:

- an internal operations/research portal
- reusable Hermes-style analyst skills
- a local VirtualBox malware-analysis sandbox
- optional OpenCTI report ingestion scaffolding
- deployment scripts that are easy to customize for each organization
- a SOAR-capable portal shell with cases, playbooks, approvals, workflow runs, and grouped operator navigation

This repository intentionally ships without organization branding, private data, report artifacts, credentials, or live environment state. Treat it as a skeleton: clone it, add your own branding, tune workflows, and wire it into your own infrastructure.

## What is included

```text
components/
  portal/                 FastAPI + SQLite operations portal
  local-sandbox/          Local VirtualBox malware-analysis sandbox runner
skills/                   Reusable analyst workflow skills/templates
deploy/
  systemd/                Example service units
  opencti/                Optional local OpenCTI compose skeleton
scripts/                  Bootstrap, smoke-test, and sanitization helpers
docs/                     Architecture and rollout notes
```

## Portal feature highlights

The packaged portal now includes more than basic intake and tracking. The current shell covers:

- grouped navigation for `Command`, `Investigations`, `Client Delivery`, and `Admin`
- `/soar` command center for open cases, pending approvals, active workflow runs, and playbook inventory
- `/cases` and `/cases/{case_id}` for case summaries, timelines, artifacts, linked tasks, and related playbooks
- `/playbooks` for catalog browsing, launch actions, and recent workflow-run visibility
- `/approvals` for approval queue review and higher-risk operator holds
- authenticated JSON endpoints for case list/detail/create, playbook launch, and workflow-run status changes
- extracted workflow service modules under `components/portal/portal/services/` for registry and workflow engine logic

## Quick start: local portal

Prerequisites:
- Linux, macOS, or WSL2 for the portal
- Python 3.10+
- `uv` recommended, or `python3 -m venv`
- optional: Hermes CLI if you want AI-backed workflow dispatch

```bash
git clone git@github.com:lost0x01/Full-RAIccoon-Package.git
cd Full-RAIccoon-Package
cp .env.example .env
scripts/bootstrap.sh
scripts/run-portal.sh
```

Open:

```text
http://127.0.0.1:8008
```

Default bootstrap credentials are only for first boot:

```text
username: admin
password: change-me-now
```

Change them in `.env` before any shared deployment.

## Quick start: local sandbox

The sandbox is local-first and assumes you maintain isolated VirtualBox guests.

Required host tools vary by workflow, but commonly include:
- VirtualBox / VBoxManage
- tshark / capinfos
- dnsmasq
- 7z
- xorriso
- OpenSSL
- optional REMnux analysis VM
- optional Suricata, YARA, Volatility, python-evtx

```bash
cd components/local-sandbox
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
python3 -m raiccoon_sandbox.local_vbox_detonate --help
```

Never bridge malware VMs to production networks. Use host-only networking and handle all artifacts as potentially malicious.

### WSL2 note

The portal and skills work normally in WSL2. The malware sandbox can use Windows-host Oracle VirtualBox through the WSL adapter in:

```text
components/local-sandbox/adapters/wsl/
```

Start with:

```bash
cd components/local-sandbox
adapters/wsl/setup-wsl-vboxmanage.sh
```

Then read:

```text
components/local-sandbox/docs/wsl-windows-virtualbox.md
```

WSL mode is best treated as an advanced bridge. Validate host-only networking, DNS simulation, packet capture, and Guest Additions before using it for real samples. A dedicated Linux lab host remains the recommended high-assurance malware-analysis deployment.

## Optional OpenCTI

`deploy/opencti/docker-compose.yml` is a starter compose file for teams that want local OpenCTI. It is intentionally generic and requires you to provide secrets in a local `.env` file.

The portal and report workflows can be tuned to publish final reports into OpenCTI as Report objects. Purple-team/RFI style workflows should keep their visible report family separate from their OpenCTI classification.

## Branding and tuning

Add your organization-specific material in these places:

- `components/portal/static/` for logo/CSS assets
- `components/portal/templates/` for navigation labels and page copy
- `.env` for portal title/admin/runtime settings
- `skills/` for internal analyst playbooks
- `skills/hermes-opencti-redteam-skill-setup/` for installing the community `redteam-threat-exploits` Hermes skill and wiring it to local OpenCTI
- `components/local-sandbox/configs/local.example.yaml` for VM names, snapshots, and network values

Avoid committing:
- API tokens
- real client names
- report PDFs/DOCX
- malware samples
- detonation outputs
- portal SQLite databases
- private OpenCTI credentials

## Deployment model

Recommended rollout for a small team:

1. Clone this repo on an internal host.
2. Copy `.env.example` to `.env` and set a real secret/admin password.
3. Bind the portal to localhost first.
4. Put it behind VPN/Tailscale/reverse proxy before exposing it to a team.
5. Configure CIDR allowlisting in both the app and reverse proxy.
6. Install the systemd unit after local smoke tests pass.
7. Only then add branding, OpenCTI, and sandbox VM details.

## Commands

```bash
# bootstrap portal venv and local dirs
scripts/bootstrap.sh

# run portal in foreground
scripts/run-portal.sh

# run basic repository checks
scripts/smoke-test.sh

# scan for common private branding/secrets before publishing
scripts/sanitize-check.sh
```

Focused portal verification after the SOAR/navigation tranche:

```bash
cd components/portal
python3 -m py_compile app.py
PYTHONPATH=$PWD uv run --with-requirements requirements.txt --with pytest --with httpx pytest tests/test_task_routes.py -q
PYTHONPATH=$PWD uv run --with-requirements requirements.txt --with pytest --with httpx pytest tests/test_soar_porting.py -q
```

## Security notes

- CIDR allowlisting in the app is defense-in-depth, not your only boundary.
- Use network controls: VPN, Tailscale, firewall rules, SSO/reverse proxy, or VLAN ACLs.
- Rotate bootstrap credentials before real use.
- Do not expose the malware sandbox to untrusted users.
- Do not store samples or analysis outputs in Git.

## Status

This is a working skeleton extracted from an internal deployment pattern and sanitized for reuse. It is intended to get partner organizations to a useful starting point quickly while leaving room for their own branding, workflow tuning, and security controls.
