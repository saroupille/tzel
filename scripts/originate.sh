#!/usr/bin/env bash
# Originate the TzEL smart rollup (one-off per testnet).
#
# Prerequisites:
#   - octez-node is running and synced (octez-client volume populated)
#   - operator key imported: see scripts/import-key.sh
#   - .env has TZEL_SOURCE_ALIAS set
#
# After running, update .env:
#   TZEL_ROLLUP_ADDRESS=<output sr1...>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

if [[ -f .env ]]; then
  set -a; source .env; set +a
fi

SOURCE_ALIAS="${TZEL_SOURCE_ALIAS:-tzelshadownet}"

echo "→ Building tzel-originator image..."
docker buildx build \
  -f docker/Dockerfile.kernel \
  -t tzel-originator \
  --load \
  .

echo "→ Reading kernel WASM hex..."
KERNEL_HEX=$(docker run --rm tzel-originator \
  sh -c 'xxd -p -c0 /kernel/tzel_rollup_kernel.wasm')

echo "→ Originating smart rollup (alias: ${SOURCE_ALIAS})..."
RESULT=$(docker run --rm \
  -v octez-client:/var/lib/tzel/octez-client \
  tzel-originator \
    --base-dir /var/lib/tzel/octez-client \
    --endpoint http://octez-node:8732 \
    originate smart rollup tzel-rollup \
    from "${SOURCE_ALIAS}" \
    of kind wasm_2_0_0 \
    of type bytes \
    booting with "${KERNEL_HEX}")

echo "${RESULT}"

ROLLUP_ADDR=$(echo "${RESULT}" | grep -oE 'sr1[a-zA-Z0-9]+' | head -1)

if [[ -z "${ROLLUP_ADDR}" ]]; then
  echo "✗ Could not extract rollup address from output." >&2
  exit 1
fi

echo "→ Rollup address: ${ROLLUP_ADDR}"

sed -i "s|TZEL_ROLLUP_ADDRESS=.*|TZEL_ROLLUP_ADDRESS=${ROLLUP_ADDR}|" .env
echo "✓ .env updated: TZEL_ROLLUP_ADDRESS=${ROLLUP_ADDR}"
