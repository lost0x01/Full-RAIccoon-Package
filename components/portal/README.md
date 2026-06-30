# RAIccoon Operations Portal

A brand-neutral FastAPI/SQLite portal for internal analyst operations. It includes request intake, task tracking, document/report handling, optional Hermes CLI dispatch, a SOAR command center, cases, playbooks, approvals, workflow runs, and deployment examples.

## Run

```bash
cd components/portal
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Default URL: `http://127.0.0.1:8008`.

Use the repository root `.env.example` for runtime configuration.

## Important

- Rotate bootstrap credentials before team use.
- Put the portal behind VPN/firewall/reverse-proxy controls.
- Do not commit `data/`, reports, uploads, or SQLite DB files.
