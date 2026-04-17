.PHONY: up down reset build logs originate import-key

# ── Local Docker stack ────────────────────────────────────────────────────────

## Start all services
up:
	docker compose up -d

## Stop all services, preserve volumes
down:
	docker compose down

## Wipe all state (volumes included) — re-origination required after this
reset:
	docker compose down -v

## Build (or rebuild) all images
build:
	docker compose build

## Stream logs for all services (Ctrl-C to stop)
logs:
	docker compose logs -f

## Stream logs for a single service: make logs-SERVICE (e.g. make logs-tzel-operator)
logs-%:
	docker compose logs -f $*

## Open a shell in a running container: make shell-SERVICE
shell-%:
	docker compose exec $* /bin/sh

# ── First-time setup ──────────────────────────────────────────────────────────

## Import operator signing key (run once before originate)
## Usage: make import-key KEY=unencrypted:edsk...
import-key:
	@bash scripts/import-key.sh "$(KEY)"

## Originate the TzEL smart rollup (run once per testnet, after import-key)
originate:
	@bash scripts/originate.sh
