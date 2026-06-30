---
name: hermes-opencti-redteam-skill-setup
description: Use when installing the redteam-threat-exploits skill into a Hermes profile and wiring it to a local OpenCTI instance with a reusable launcher.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [hermes, opencti, redteam, skills, profile-setup]
    related_skills: [hermes-agent, redteam-threat-exploits]
---

# Hermes OpenCTI red-team skill setup

## Overview

This skill captures the repeatable setup for making the community skill
`redteam-threat-exploits` usable in a local Hermes environment. It installs the
skill from GitHub, wires `OPENCTI_URL` and `OPENCTI_TOKEN` into the target
Hermes profile, patches the installed skill when the host's OpenCTI base URL is
known to differ from the upstream default, and adds a small wrapper command so
future use does not require manual environment preparation.

Use this when setting up a new host or Hermes profile for threat-informed red
team workflows backed by a local OpenCTI deployment.

## When to Use

- You want `redteam-threat-exploits` available in Hermes on a local machine.
- Hermes should automatically know the local OpenCTI URL and token.
- You want a repeatable launcher such as `hermes-redteam-threats`.
- You are moving this workflow to another Hermes profile or another operator
  workstation.

Do not use this when:
- The user only wants to inspect the upstream repo without installing it.
- The target OpenCTI instance is remote and the local host assumptions below do
  not apply.
- The user has not authorized copying an OpenCTI token into the target Hermes
  profile.

## Assumptions for this host

On this host, local OpenCTI is reachable at:
- `http://127.0.0.1:8088`

The deployed OpenCTI secrets currently live under:
- `/home/lost0x01/services/opencti-deploy/.env`

The default Hermes profile paths are:
- `~/.hermes/config.yaml`
- `~/.hermes/.env`

## Setup steps

1. Install or update the source repo locally.

```bash
git clone https://github.com/mochiCoon/redteam-threat-exploits.git ~/github/redteam-threat-exploits
```

If the repo already exists, update it instead:

```bash
git -C ~/github/redteam-threat-exploits pull --ff-only
```

2. Add the repo as a Hermes skill tap.

```bash
hermes skills tap add mochiCoon/redteam-threat-exploits
```

3. Install the skill from the raw GitHub `SKILL.md` URL.

```bash
hermes skills install \
  https://raw.githubusercontent.com/mochiCoon/redteam-threat-exploits/main/SKILL.md \
  --category red-teaming \
  --yes
```

4. Verify the skill is installed.

```bash
hermes skills list | grep -i redteam-threat-exploits
```

5. Back up the target Hermes profile env file before editing.

```bash
cp ~/.hermes/.env ~/.hermes/.env.pre-opencti-redteam-setup.$(date +%Y%m%d%H%M%S).bak
```

6. Populate `OPENCTI_URL` and `OPENCTI_TOKEN` in `~/.hermes/.env`.

Recommended values for this host:
- `OPENCTI_URL=http://127.0.0.1:8088`
- `OPENCTI_TOKEN=<value sourced from /home/lost0x01/services/opencti-deploy/.env>`

Do not print the token into chat or logs. Read it from the deploy env and write
it directly into the target Hermes profile env.

7. Patch the installed skill if the upstream instructions assume the wrong local
base URL.

Target file:
- `~/.hermes/skills/red-teaming/redteam-threat-exploits/SKILL.md`

Adjust Step 1 so it prefers `http://127.0.0.1:8088` when `OPENCTI_URL` is
unset, while still requiring a real token.

8. Create a reusable launcher in `~/.local/bin/hermes-redteam-threats`.

Recommended wrapper behavior:
- load `~/.hermes/.env`
- if `OPENCTI_TOKEN` is missing, source `~/services/opencti-deploy/.env`
- export `OPENCTI_TOKEN` from `OPENCTI_ADMIN_TOKEN` when available
- default `OPENCTI_URL` to `http://127.0.0.1:8088`
- exec `hermes -s redteam-threat-exploits "$@"`
- support a `--check` mode that prints only non-secret health data

Reference wrapper:

```bash
#!/usr/bin/env bash
set -euo pipefail

HERMES_ENV="$HOME/.hermes/.env"
DEPLOY_ENV="$HOME/services/opencti-deploy/.env"
DEFAULT_OPENCTI_URL="http://127.0.0.1:8088"

load_env_file() {
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi
}

load_env_file "$HERMES_ENV"

if [[ -z "${OPENCTI_TOKEN:-}" && -f "$DEPLOY_ENV" ]]; then
  load_env_file "$DEPLOY_ENV"
  if [[ -n "${OPENCTI_ADMIN_TOKEN:-}" ]]; then
    export OPENCTI_TOKEN="$OPENCTI_ADMIN_TOKEN"
  fi
fi

export OPENCTI_URL="${OPENCTI_URL:-$DEFAULT_OPENCTI_URL}"

if [[ "${1:-}" == "--check" ]]; then
  python3 - <<'PY'
import os
import urllib.request
url = os.environ.get('OPENCTI_URL', '')
token_set = bool(os.environ.get('OPENCTI_TOKEN'))
print(f'OPENCTI_URL={url or "<unset>"}')
print(f'OPENCTI_TOKEN_SET={str(token_set).lower()}')
if url:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            print(f'OPENCTI_HTTP_STATUS={r.status}')
    except Exception as e:
        print(f'OPENCTI_HTTP_STATUS=unreachable:{e}')
else:
    print('OPENCTI_HTTP_STATUS=skipped-no-url')
print('SKILL=redteam-threat-exploits')
PY
  exit 0
fi

exec hermes -s redteam-threat-exploits "$@"
```

Then:

```bash
chmod +x ~/.local/bin/hermes-redteam-threats
```

## Verification

Run these checks:

```bash
hermes skills inspect https://raw.githubusercontent.com/mochiCoon/redteam-threat-exploits/main/SKILL.md
hermes-redteam-threats --check
hermes-redteam-threats chat -q 'Using the loaded redteam-threat-exploits skill, reply with only the default local OpenCTI base URL for this environment.' -Q
```

Expected outcomes:
- the skill inspects and installs cleanly
- `--check` reports `OPENCTI_URL=http://127.0.0.1:8088`
- `OPENCTI_TOKEN_SET=true`
- the HTTP health check returns 200 when local OpenCTI is up
- the one-shot smoke test returns `http://127.0.0.1:8088`

## Common Pitfalls

1. Writing `OPENCTI_URL` as `http://127.0.0.1:8080` on this host. The local
   service is on `8088`.

2. Copying the token into chat output, shell history, or notes. Read it from the
   deploy env and write it directly into the Hermes profile env without
   displaying it.

3. Forgetting that existing Hermes sessions cache environment state. After
   editing `~/.hermes/.env`, use `/reload` in a running session or start a new
   session.

4. Assuming the installed community skill exactly matches the local deployment.
   Verify and patch the installed SKILL.md when the host-specific OpenCTI URL or
   workflow differs.

5. Creating the wrapper without `chmod +x`, which makes it look missing even
   when the file exists.

## Verification Checklist

- [ ] Repo exists at `~/github/redteam-threat-exploits`
- [ ] Tap `mochiCoon/redteam-threat-exploits` is added
- [ ] Skill installed at `~/.hermes/skills/red-teaming/redteam-threat-exploits/SKILL.md`
- [ ] `~/.hermes/.env` contains `OPENCTI_URL` and `OPENCTI_TOKEN`
- [ ] Wrapper exists at `~/.local/bin/hermes-redteam-threats`
- [ ] Wrapper passes `--check` without exposing secrets
- [ ] Hermes one-shot smoke test returns `http://127.0.0.1:8088`
