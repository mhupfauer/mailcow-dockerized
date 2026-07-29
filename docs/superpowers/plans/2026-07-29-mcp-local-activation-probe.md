# MCP Local Activation Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the MCP activation readiness check connect directly to Mailcow's loopback HTTPS listener with certificate verification disabled while preserving the public MCP URLs, Host header, SNI, issuer, and resource identity.

**Architecture:** Add one versioned, non-secret `mailcow.conf` switch that is disabled by default and validated by the shared MCP configuration helper. When enabled, `mcp_verify_https` supplies a fixed loopback `curl --connect-to` mapping and `--insecure` to all three existing contract probes; no runtime container or public endpoint configuration changes.

**Tech Stack:** Bash, curl, jq, Mailcow's versioned `mailcow.conf` migration, shell integration tests.

## Global Constraints

- The setting is named `MCP_ACTIVATION_LOCAL_VERIFY` and accepts only `0` or `1`.
- The default is `0`; existing installations receive it without changing existing secrets or explicit values.
- Local mode connects to `127.0.0.1`, never an operator-provided target.
- Local mode uses `HTTPS_PORT` from `mailcow.conf`, defaulting to `443` when absent; an explicit value must be an integer from 1 through 65535.
- Probe URLs remain `https://${MAILCOW_HOSTNAME}` and all existing metadata and challenge assertions remain strict.
- `--insecure` applies only to activation readiness curl calls, not MCP runtime traffic.
- Do not add load-balancer autodetection, Compose changes, database changes, or public certificate management.
- Do not deploy the change.

---

## File Structure

- `_modules/scripts/mcp_config.sh`: owns the migrated default and validates the activation mode and local HTTPS port before lifecycle state changes.
- `helper-scripts/mcp.sh`: translates the validated local mode into curl connection options for the existing readiness contract.
- `helper-scripts/dev_tests/test_mcp_config.sh`: covers migration, preservation, and invalid configuration behavior.
- `helper-scripts/dev_tests/test_mcp_lifecycle.sh`: covers strict/default curl behavior, local loopback routing, public URL preservation, and pre-activation failure.
- `docs/manual-guides/MCP.md`: tells load-balanced operators how to select and interpret local verification.

### Task 1: Configuration Migration and Validation

**Files:**

- Modify: `_modules/scripts/mcp_config.sh:68-190`
- Test: `helper-scripts/dev_tests/test_mcp_config.sh:33-145`

**Interfaces:**

- Consumes: existing `mcp_config_value`, `mcp_config_has_key`, `mcp_append_if_missing`, and `mcp_prepare_config` functions.
- Produces: a required `MCP_ACTIVATION_LOCAL_VERIFY` value after migration; `mcp_validate_config <path> <enabled|disabled>` rejects invalid mode values and, in local mode, invalid explicit `HTTPS_PORT` values.

- [ ] **Step 1: Add failing migration and validation tests**

Add the new default to `expected_defaults`:

```bash
'MCP_ACTIVATION_LOCAL_VERIFY=0'
```

Add this focused test utility after `secret_hashes`:

```bash
replace_config_value() {
  local path="$1"
  local key="$2"
  local value="$3"
  local next="${path}.next"

  awk -F= -v key="${key}" -v value="${value}" '
    $1 == key { print key "=" value; matches++; next }
    { print }
    END { if (matches != 1) exit 1 }
  ' "${path}" > "${next}" || {
    rm -f -- "${next}"
    return 1
  }
  mv "${next}" "${path}"
}
```

Add a focused test that prepares a versioned configuration with
`MCP_ACTIVATION_LOCAL_VERIFY=1` and `HTTPS_PORT=8443`, runs
`mcp_prepare_config`, and asserts both values and the existing secret hash are
preserved. Add table-driven invalid cases for activation mode `yes` and local
ports `0`, `65536`, and `not-a-port`; each must make `mcp_prepare_config` fail
without changing the original file bytes:

```bash
test_activation_local_verify_migration_and_validation() {
  local case_dir="${TEST_DIR}/local-verify"
  local config_path="${case_dir}/mailcow.conf"
  local before_hash
  local invalid
  local invalid_path
  local invalid_value

  mkdir -p "${case_dir}"
  printf 'MAILCOW_HOSTNAME=mail.example.test\n' > "${config_path}"
  mcp_prepare_config "${config_path}" upgrade
  grep -qx 'MCP_ACTIVATION_LOCAL_VERIFY=0' "${config_path}" ||
    fail "local activation verification did not default to strict mode"

  replace_config_value "${config_path}" MCP_ACTIVATION_LOCAL_VERIFY 1
  printf 'HTTPS_PORT=8443\n' >> "${config_path}"
  before_hash="$(secret_hashes "${config_path}")"
  mcp_prepare_config "${config_path}" upgrade
  grep -qx 'MCP_ACTIVATION_LOCAL_VERIFY=1' "${config_path}" ||
    fail "explicit local activation verification was not preserved"
  grep -qx 'HTTPS_PORT=8443' "${config_path}" ||
    fail "explicit HTTPS port was not preserved"
  test "${before_hash}" = "$(secret_hashes "${config_path}")" ||
    fail "local verification migration changed existing secrets"

  for invalid in mode port-zero port-high port-text; do
    invalid_path="${case_dir}/${invalid}.conf"
    cp "${config_path}" "${invalid_path}"
    case "${invalid}" in
      mode)
        replace_config_value "${invalid_path}" \
          MCP_ACTIVATION_LOCAL_VERIFY yes
        ;;
      port-zero)
        invalid_value=0
        replace_config_value "${invalid_path}" HTTPS_PORT "${invalid_value}"
        ;;
      port-high)
        invalid_value=65536
        replace_config_value "${invalid_path}" HTTPS_PORT "${invalid_value}"
        ;;
      port-text)
        invalid_value=not-a-port
        replace_config_value "${invalid_path}" HTTPS_PORT "${invalid_value}"
        ;;
    esac
    before_hash="$(sha256sum "${invalid_path}" | awk '{print $1}')"
    if mcp_prepare_config "${invalid_path}" upgrade >/dev/null 2>&1; then
      fail "invalid local activation configuration ${invalid} succeeded"
    fi
    test "${before_hash}" = \
      "$(sha256sum "${invalid_path}" | awk '{print $1}')" ||
      fail "invalid local activation configuration ${invalid} mutated the file"
  done
  pass "local activation verification migrates and validates safely"
}
```

Register the test in the invocation list at the bottom of the test file.

- [ ] **Step 2: Run the configuration tests and confirm the new assertions fail**

Run:

```bash
bash helper-scripts/dev_tests/test_mcp_config.sh
```

Expected: FAIL because the migrated default and validation do not exist yet.

- [ ] **Step 3: Implement the migrated default and validation**

In `mcp_validate_config`, add local variables for the mode and HTTPS port. Add
`MCP_ACTIVATION_LOCAL_VERIFY` to `default_keys`, then validate:

```bash
activation_local_verify="$(
  mcp_config_value "${config_path}" MCP_ACTIVATION_LOCAL_VERIFY
)" || {
  echo "MCP_ACTIVATION_LOCAL_VERIFY must be set exactly once" >&2
  return 1
}
[[ "${activation_local_verify}" =~ ^[01]$ ]] || {
  echo "MCP_ACTIVATION_LOCAL_VERIFY must be 0 or 1" >&2
  return 1
}

if [[ "${activation_local_verify}" == 1 ]] &&
  mcp_config_has_key "${config_path}" HTTPS_PORT; then
  https_port="$(mcp_config_value "${config_path}" HTTPS_PORT)" || {
    echo "HTTPS_PORT must be set at most once for MCP local activation verification" >&2
    return 1
  }
  if [[ ! "${https_port}" =~ ^[0-9]{1,5}$ ]] ||
    (( 10#${https_port} < 1 || 10#${https_port} > 65535 )); then
    echo "HTTPS_PORT must be an integer from 1 through 65535 for MCP local activation verification" >&2
    return 1
  fi
fi
```

In `mcp_append_defaults`, append:

```bash
mcp_append_if_missing "${config_path}" MCP_ACTIVATION_LOCAL_VERIFY 0
```

The absence of `HTTPS_PORT` is valid and means port 443. Do not append or
rewrite `HTTPS_PORT`.

- [ ] **Step 4: Run the configuration tests and syntax checks**

Run:

```bash
bash -n _modules/scripts/mcp_config.sh helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_config.sh
```

Expected: both commands exit 0 and the test output includes the new local
activation migration/validation PASS line.

- [ ] **Step 5: Commit the configuration contract**

```bash
git add _modules/scripts/mcp_config.sh helper-scripts/dev_tests/test_mcp_config.sh
git commit -m "feat: configure local MCP activation verification"
```

### Task 2: Loopback Readiness Probe and Operator Documentation

**Files:**

- Modify: `helper-scripts/mcp.sh:293-365`
- Test: `helper-scripts/dev_tests/test_mcp_lifecycle.sh:23-65,192-266,320-360,650-715`
- Modify: `docs/manual-guides/MCP.md:39-58`

**Interfaces:**

- Consumes: validated `MCP_ACTIVATION_LOCAL_VERIFY`, optional `HTTPS_PORT`, and existing `MAILCOW_HOSTNAME` values from `mailcow.conf`.
- Produces: `mcp_verify_https` adds `--insecure --connect-to "${hostname}:443:127.0.0.1:${https_port}"` to every readiness curl request only when local mode is `1`.

- [ ] **Step 1: Add failing lifecycle tests for strict and local probe modes**

Add `MCP_ACTIVATION_LOCAL_VERIFY=0` to `write_config`. Add a test helper that
replaces exactly one configuration key without modifying other bytes:

```bash
set_config_value() {
  local path="$1"
  local key="$2"
  local value="$3"
  local next="${path}.next"

  awk -F= -v key="${key}" -v value="${value}" '
    $1 == key { print key "=" value; matches++; next }
    { print }
    END { if (matches != 1) exit 1 }
  ' "${path}" > "${next}" || {
    rm -f -- "${next}"
    return 1
  }
  mv "${next}" "${path}"
}
```

Add `test_https_verification_supports_local_backend_mode`:

```bash
test_https_verification_supports_local_backend_mode() {
  local case_dir
  local curl_count

  case_dir="$(make_case strict-readiness)"
  run_mcp "${case_dir}" enable >/dev/null
  if grep '^curl ' "${case_dir}/calls.log" |
    grep -Eq -- '--insecure|--connect-to'; then
    fail "strict readiness weakened TLS or bypassed the public destination"
  fi

  case_dir="$(make_case local-readiness-default-port)"
  set_config_value "${case_dir}/mailcow.conf" MCP_ACTIVATION_LOCAL_VERIFY 1
  run_mcp "${case_dir}" enable >/dev/null
  curl_count="$(grep -c '^curl ' "${case_dir}/calls.log")"
  test "${curl_count}" = 3 ||
    fail "local readiness did not execute the complete contract"
  test "$(grep -c -- '--insecure' "${case_dir}/calls.log")" = 3 ||
    fail "local readiness did not allow the backend certificate on every request"
  test "$(grep -c -- \
    '--connect-to mail.example.test:443:127.0.0.1:443' \
    "${case_dir}/calls.log")" = 3 ||
    fail "local readiness did not default to the loopback HTTPS port"
  test "$(grep -c 'https://mail.example.test' "${case_dir}/calls.log")" = 3 ||
    fail "local readiness changed a public request URL"

  case_dir="$(make_case local-readiness-custom-port)"
  set_config_value "${case_dir}/mailcow.conf" MCP_ACTIVATION_LOCAL_VERIFY 1
  printf 'HTTPS_PORT=8443\n' >> "${case_dir}/mailcow.conf"
  run_mcp "${case_dir}" enable >/dev/null
  test "$(grep -c -- \
    '--connect-to mail.example.test:443:127.0.0.1:8443' \
    "${case_dir}/calls.log")" = 3 ||
    fail "local readiness ignored the configured HTTPS port"

  pass "HTTPS verification supports a fixed local backend mode"
}
```

Add `test_invalid_local_probe_config_aborts_before_activation`, configuring
local mode with `HTTPS_PORT=70000`:

```bash
test_invalid_local_probe_config_aborts_before_activation() {
  local case_dir

  case_dir="$(make_case invalid-local-readiness)"
  set_config_value "${case_dir}/mailcow.conf" MCP_ACTIVATION_LOCAL_VERIFY 1
  printf 'HTTPS_PORT=70000\n' >> "${case_dir}/mailcow.conf"
  cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

  if run_mcp "${case_dir}" enable >/dev/null 2>&1; then
    fail "enable accepted an invalid local readiness HTTPS port"
  fi
  assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
    "invalid local readiness configuration was not restored exactly"
  if grep -qx 'config' "${case_dir}/stages.log" 2>/dev/null; then
    fail "invalid local readiness configuration reached activation"
  fi
  if grep -q '^curl ' "${case_dir}/calls.log" 2>/dev/null; then
    fail "invalid local readiness configuration reached an HTTPS probe"
  fi

  pass "invalid local probe configuration aborts before activation"
}
```

Register both tests near the existing HTTPS verification test in the bottom
invocation list.

- [ ] **Step 2: Run the focused lifecycle tests and confirm they fail**

Add a `local-probe` focus branch next to the existing test focus branches:

```bash
if [[ "${MCP_TEST_FOCUS:-}" == local-probe ]]; then
  test_https_verification_supports_local_backend_mode
  test_invalid_local_probe_config_aborts_before_activation
  exit 0
fi
```

Run:

```bash
MCP_TEST_FOCUS=local-probe bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
```

Expected: FAIL because `mcp_verify_https` does not yet add either curl option.
Keep the focus branch as a useful fast regression target.

- [ ] **Step 3: Implement the local curl connection options**

In `mcp_verify_https`, add:

```bash
local activation_local_verify
local https_port=443
local -a curl_connection_options=()
```

After reading `MAILCOW_HOSTNAME`, read the already-validated mode and build the
options:

```bash
activation_local_verify="$(
  mcp_config_value "${MAILCOW_CONF}" MCP_ACTIVATION_LOCAL_VERIFY
)" || {
  echo "MCP_ACTIVATION_LOCAL_VERIFY must be set exactly once" >&2
  return 1
}
if [[ "${activation_local_verify}" == 1 ]]; then
  if mcp_config_has_key "${MAILCOW_CONF}" HTTPS_PORT; then
    https_port="$(mcp_config_value "${MAILCOW_CONF}" HTTPS_PORT)" || {
      echo "HTTPS_PORT must be set at most once for MCP local activation verification" >&2
      return 1
    }
  fi
  curl_connection_options=(
    --insecure
    --connect-to "${hostname}:443:127.0.0.1:${https_port}"
  )
fi
```

Add `"${curl_connection_options[@]}"` to each of the three existing curl
commands before their output/header arguments. Do not change the URL
expressions, response parsing, retry bounds, or rollback behavior.

- [ ] **Step 4: Run the focused lifecycle tests**

Run:

```bash
bash -n helper-scripts/mcp.sh helper-scripts/dev_tests/test_mcp_lifecycle.sh
MCP_TEST_FOCUS=local-probe bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
```

Expected: both commands exit 0; the focused run prints PASS lines for local
backend mode and pre-activation rejection.

- [ ] **Step 5: Document the load-balancer mode**

Add a subsection after the `enable`/`retry` explanation:

````markdown
### Readiness verification behind a load balancer

The activation check uses the public Mailcow HTTPS address by default. If the
Mailcow host cannot hairpin through its load balancer, set this in
`mailcow.conf` before running `enable` or `retry`:

```dotenv
MCP_ACTIVATION_LOCAL_VERIFY=1
```

In this mode the helper keeps the public hostname and MCP URLs but connects to
`127.0.0.1:${HTTPS_PORT:-443}` and accepts the local Mailcow certificate. This
checks local nginx routing and the MCP discovery/authentication contract; it
does not validate load-balancer health or public certificate trust. MCP client
traffic still uses the public endpoint.
````

- [ ] **Step 6: Run the complete MCP shell regression suite**

Run:

```bash
bash helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
bash -n _modules/scripts/mcp_config.sh helper-scripts/mcp.sh \
  helper-scripts/dev_tests/test_mcp_config.sh \
  helper-scripts/dev_tests/test_mcp_lifecycle.sh
git diff --check
```

Expected: all commands exit 0, all MCP lifecycle PASS lines are present, and
`git diff --check` prints nothing.

- [ ] **Step 7: Commit the probe and documentation**

```bash
git add helper-scripts/mcp.sh \
  helper-scripts/dev_tests/test_mcp_lifecycle.sh \
  docs/manual-guides/MCP.md
git commit -m "fix: support local MCP activation probes"
```

### Task 3: Final Review and Verification

**Files:**

- Review only: all files changed by Tasks 1 and 2.

**Interfaces:**

- Consumes: the complete configuration and lifecycle implementation.
- Produces: review evidence that the implementation matches the approved design and introduces no unrelated changes.

- [ ] **Step 1: Review the branch diff against the design**

Run:

```bash
git diff 427eb175..HEAD -- \
  _modules/scripts/mcp_config.sh \
  helper-scripts/mcp.sh \
  helper-scripts/dev_tests/test_mcp_config.sh \
  helper-scripts/dev_tests/test_mcp_lifecycle.sh \
  docs/manual-guides/MCP.md
```

Confirm the diff contains only:

- one migrated and validated activation setting;
- fixed loopback connection options limited to readiness curl calls;
- tests for strict mode, local mode, port selection, public URLs, migration,
  validation, and activation abort behavior; and
- operator documentation.

- [ ] **Step 2: Re-run final verification**

Run:

```bash
bash helper-scripts/dev_tests/test_mcp_config.sh
bash helper-scripts/dev_tests/test_mcp_lifecycle.sh
git status --short
```

Expected: both test scripts exit 0. Git status shows only the user's unrelated
untracked `.DS_Store` files and no uncommitted implementation changes.

- [ ] **Step 3: Record final evidence**

Report the two implementation commit hashes, the exact test commands and
results, the new operator setting, and the fact that no deployment occurred.
Also state that the missing protected-resource metadata endpoint remains a
separate activation blocker.
