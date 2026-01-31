# cronsible
Agentless, distributed cron system powered by Ansible.

## Features
- Single Go binary with embedded web UI
- SQLite storage
- Hosts + groups inventory
- Cron jobs targeting a host or group
- Ansible CLI execution with uploaded/generated SSH keys
- Simple schedule helper ("AI") to suggest cron expressions

## Requirements
- Go 1.22+
- Ansible CLI available in `$PATH`
- `ssh-keygen` for key generation (or upload a key instead)

## Quick start
```bash
# from this repo
mkdir -p data

go run .
```
Then visit http://localhost:8080 and complete the setup.

## Configuration
Environment variables:
- `CRONSIBLE_ADDR` (default `:8080`)
- `CRONSIBLE_DATA_DIR` (default `./data`)
- `CRONSIBLE_ANSIBLE_PATH` (default `ansible`)

The inventory file is written to `<data-dir>/inventory.ini`.

## Notes
- Jobs are executed sequentially (concurrency = 1).
- Inventory is regenerated before each job run.
- Private keys are stored unencrypted in the data directory.
