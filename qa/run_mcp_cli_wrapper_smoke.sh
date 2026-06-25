#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bastion-mcp-cli-wrapper-smoke.XXXXXX")"
trap 'rm -rf "$SMOKE_DIR"' EXIT

FAKE_CLI="$SMOKE_DIR/bastion-cli"
cat >"$FAKE_CLI" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  "status")
    printf '%s\n' '{"version":"test","serviceRegistrationStatus":"enabled","configCorrupted":false}'
    ;;
  "rules")
    printf '%s\n' "Error: Error: Pair this client with Bastion before reading pubkey, rules, or state." >&2
    exit 1
    ;;
  "groups list")
    printf '%s\n' "Error: Error: Request timed out" >&2
    exit 1
    ;;
  *)
    printf 'unexpected fake CLI invocation: %s\n' "$*" >&2
    exit 64
    ;;
esac
SH
chmod 755 "$FAKE_CLI"

BASTION_CLI_PATH="$FAKE_CLI" bun --cwd mcp --eval '
  const cli = await import("./src/cli.ts");
  const status = await cli.status();
  if (status.version !== "test" || status.serviceRegistrationStatus !== "enabled") {
    throw new Error(`status JSON parse failed: ${JSON.stringify(status)}`);
  }

  async function expectMessage(label, fn, expected) {
    try {
      await fn();
      throw new Error(`${label} unexpectedly succeeded`);
    } catch (error) {
      if (error.message !== expected) {
        throw new Error(`${label} produced ${JSON.stringify(error.message)}, expected ${JSON.stringify(expected)}`);
      }
      if (error.message.includes("Error: Error:")) {
        throw new Error(`${label} leaked a duplicate Error prefix`);
      }
    }
  }

  await expectMessage(
    "rules",
    () => cli.rules(),
    "Pair this client with Bastion before reading pubkey, rules, or state.",
  );
  await expectMessage(
    "listWalletGroups",
    () => cli.listWalletGroups(),
    "List wallet groups timed out — ensure the signed Bastion service is running and update to a build where read-only group listing does not require owner authentication",
  );
'
