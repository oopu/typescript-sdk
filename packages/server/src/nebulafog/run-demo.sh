#!/usr/bin/env bash
# run-demo.sh — Runs the Nebula Fog gossip-prevention demo.
#
# Usage (from typescript-sdk/):
#   pnpm --filter @modelcontextprotocol/server demo
#
# This script creates temporary shim files that the unbuilt workspace
# packages need for module resolution, runs the demo, then cleans up.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/../../../.."

# Create minimal dist shim files (workspace packages export dist/ but build
# toolchain has a pre-existing rolldown native binding issue)
mkdir -p "$ROOT/packages/client/dist" "$ROOT/packages/server/dist"

cat > "$ROOT/packages/client/dist/shimsNode.mjs" << 'EOF'
export { AjvJsonSchemaValidator as DefaultJsonSchemaValidator } from '../node_modules/@modelcontextprotocol/core/src/validators/ajvProvider.js';
EOF

cat > "$ROOT/packages/server/dist/shimsNode.mjs" << 'EOF'
export { AjvJsonSchemaValidator as DefaultJsonSchemaValidator } from '../node_modules/@modelcontextprotocol/core/src/validators/ajvProvider.js';
EOF

cleanup() {
  rm -f "$ROOT/packages/client/dist/shimsNode.mjs"
  rm -f "$ROOT/packages/server/dist/shimsNode.mjs"
  rmdir "$ROOT/packages/client/dist" 2>/dev/null || true
  rmdir "$ROOT/packages/server/dist" 2>/dev/null || true
}
trap cleanup EXIT

# Run the demo
exec npx tsx --tsconfig "$SCRIPT_DIR/../../tsconfig.json" "$SCRIPT_DIR/demo.ts"
