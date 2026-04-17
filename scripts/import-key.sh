#!/usr/bin/env bash
# Import the operator signing key into the octez-client volume.
# Run once before the first `make originate` or `make up`.
#
# Usage:
#   ./scripts/import-key.sh unencrypted:edsk...
#   ./scripts/import-key.sh ledger://... (hardware wallet)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

if [[ -f .env ]]; then
  set -a; source .env; set +a
fi

SOURCE_ALIAS="${TZEL_SOURCE_ALIAS:-tzelshadownet}"
SECRET_KEY="${1:-}"

if [[ -z "${SECRET_KEY}" ]]; then
  echo "Usage: $0 <secret-key>" >&2
  echo "  Example: $0 unencrypted:edsk..." >&2
  exit 1
fi

echo "→ Importing key as alias '${SOURCE_ALIAS}'..."
docker run --rm \
  -v octez-client:/var/lib/tzel/octez-client \
  registry.gitlab.com/tezos/tezos/octez-bare:v24.4 \
  octez-client \
    --base-dir /var/lib/tzel/octez-client \
    --endpoint http://octez-node:8732 \
    import secret key "${SOURCE_ALIAS}" "${SECRET_KEY}"

echo "✓ Key imported."
