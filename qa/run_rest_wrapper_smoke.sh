#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bastion-rest-wrapper-smoke.XXXXXX")"
trap 'rm -rf "$SMOKE_DIR"' EXIT

FAKE_CLI="$SMOKE_DIR/bastion-cli"
FAKE_LOG="$SMOKE_DIR/fake-cli.log"
cat >"$FAKE_CLI" <<SH
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "\$*" >>"$FAKE_LOG"

case "\$*" in
  "eth message hello")
    printf '%s\n' '{"pubkeyX":"01","pubkeyY":"02","r":"03","s":"04"}'
    ;;
  "sign --data 0000000000000000000000000000000000000000000000000000000000000000")
    printf '%s\n' '{"pubkeyX":"01","pubkeyY":"02","r":"03","s":"04"}'
    ;;
  "groups install-agent 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --chain 11155111 --submit --project-id project-rest --wait-seconds 10")
    printf '%s\n' '{"userOpHash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"submitted"}'
    ;;
  "groups uninstall-agent 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --chain 11155111 --wait-seconds 0")
    printf '%s\n' '{"userOpHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","status":"signed"}'
    ;;
  *)
    printf 'unexpected fake CLI invocation: %s\n' "\$*" >&2
    exit 64
    ;;
esac
SH
chmod 755 "$FAKE_CLI"
: >"$FAKE_LOG"

if ! env \
  BASTION_CLI_PATH="$FAKE_CLI" \
  BASTION_API_TOKEN="VNSq8yXf9L2mR7pT4cK6zJ1bH5wD3eQ0uA8sG9nP2vC7xY4rM6tZ1kL5hF3dB0qW" \
  bun --cwd mcp --eval '
  const server = (await import("./src/rest-server.ts")).default;
  const token = process.env.BASTION_API_TOKEN;
  const group = "11111111-1111-1111-1111-111111111111";
  const member = "22222222-2222-2222-2222-222222222222";

  async function request(path, body) {
    return await server.fetch(new Request(`http://127.0.0.1:9587${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    }));
  }

  async function expectError(label, path, body, expectedStatus, expectedMessage) {
    const response = await request(path, body);
    const payload = await response.json();
    if (response.status !== expectedStatus) {
      throw new Error(`${label} status ${response.status}, expected ${expectedStatus}: ${JSON.stringify(payload)}`);
    }
    if (payload.error !== expectedMessage) {
      throw new Error(`${label} error ${JSON.stringify(payload.error)}, expected ${JSON.stringify(expectedMessage)}`);
    }
  }

  async function expectSuccess(label, path, body, expectedStatus) {
    const response = await request(path, body);
    const payload = await response.json();
    if (response.status !== expectedStatus) {
      throw new Error(`${label} status ${response.status}, expected ${expectedStatus}: ${JSON.stringify(payload)}`);
    }
  }

  await expectError(
    "message type",
    "/sign/message",
    { message: 123 },
    400,
    "message must be a string",
  );
  await expectError(
    "group label type",
    "/groups",
    { label: 123 },
    400,
    "label must be a string",
  );
  await expectError(
    "install wait string",
    `/groups/${group}/agents/${member}/install-on-chain`,
    { chainId: 11155111, waitForReceiptSeconds: "10" },
    400,
    "waitForReceiptSeconds must be an integer from 0 to 120",
  );
  await expectError(
    "install wait range",
    `/groups/${group}/agents/${member}/install-on-chain`,
    { chainId: 11155111, waitForReceiptSeconds: 121 },
    400,
    "waitForReceiptSeconds must be an integer from 0 to 120",
  );
  await expectError(
    "uninstall submit type",
    `/groups/${group}/agents/${member}/uninstall-on-chain`,
    { chainId: 11155111, submit: "true" },
    400,
    "submit must be a boolean",
  );
  await expectSuccess(
    "message valid",
    "/sign/message",
    { message: "hello" },
    200,
  );
  await expectSuccess(
    "raw valid",
    "/sign/raw",
    { data: "0x0000000000000000000000000000000000000000000000000000000000000000" },
    200,
  );
  await expectSuccess(
    "install valid",
    `/groups/${group}/agents/${member}/install-on-chain`,
    { chainId: 11155111, submit: true, projectId: "project-rest", waitForReceiptSeconds: 10 },
    200,
  );
  await expectSuccess(
    "uninstall valid",
    `/groups/${group}/agents/${member}/uninstall-on-chain`,
    { chainId: 11155111, waitForReceiptSeconds: 0 },
    200,
  );
' >"$SMOKE_DIR/rest-smoke.out" 2>"$SMOKE_DIR/rest-smoke.err"; then
  cat "$SMOKE_DIR/rest-smoke.out"
  cat "$SMOKE_DIR/rest-smoke.err" >&2
  exit 1
fi

if grep -F "Bastion REST API starting" "$SMOKE_DIR/rest-smoke.out" "$SMOKE_DIR/rest-smoke.err" >/dev/null; then
  echo "REST server import printed startup banner during wrapper smoke" >&2
  exit 1
fi

grep -F "eth message hello" "$FAKE_LOG" >/dev/null
grep -F "sign --data 0000000000000000000000000000000000000000000000000000000000000000" "$FAKE_LOG" >/dev/null
grep -F "groups install-agent 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --chain 11155111 --submit --project-id project-rest --wait-seconds 10" "$FAKE_LOG" >/dev/null
grep -F "groups uninstall-agent 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --chain 11155111 --wait-seconds 0" "$FAKE_LOG" >/dev/null
