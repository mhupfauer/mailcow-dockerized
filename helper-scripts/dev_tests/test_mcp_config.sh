#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# The production change that makes these tests fail is a missing or non-atomic
# MCP configuration migration, an altered secret, or incorrect profile token
# handling.
source "${REPO_DIR}/_modules/scripts/mcp_config.sh"

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

pass() {
  echo "PASS: $*"
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

secret_hashes() {
  grep -E '^MCP_(DBPASS|ENCRYPTION_KEY)=' "$1" | sha256sum | awk '{print $1}'
}

assert_mcp_defaults() {
  local config_path="$1"
  local update_offered="$2"
  local expected
  local -a expected_defaults=(
    'MCP_DBNAME=mailcow_mcp'
    'MCP_DBUSER=mailcow_mcp'
    'MCP_OAUTH_ALLOWED_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback'
    'MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS=1'
    'MCP_ATTACHMENT_MAX_BYTES=10485760'
    'MCP_MESSAGE_MAX_BYTES=26214400'
    'MCP_BASE64_UPLOAD_MAX_BYTES=1048576'
    'MCP_UPLOAD_TTL_SECONDS=3600'
    'MCP_ATTACHMENT_ALLOWED_TYPES=pdf,xlsx,csv,txt,png,jpg,jpeg'
    'MCP_LOGIN_ATTEMPTS=5'
    'MCP_LOGIN_WINDOW_SECONDS=900'
    'MCP_REGISTRATIONS_PER_HOUR=10'
    'MCP_REQUESTS_PER_MINUTE=120'
    'MCP_SENDS_PER_MINUTE=10'
    'MCP_RECIPIENTS_PER_HOUR=100'
    'MCP_CONCURRENT_UPLOADS=5'
    'MCP_AUDIT_RETENTION_DAYS=30'
  )

  grep -Eq '^MCP_DBPASS=[0-9a-f]{64}$' "${config_path}" || fail "MCP_DBPASS was not generated"
  grep -Eq '^MCP_ENCRYPTION_KEY=[0-9a-f]{64}$' "${config_path}" || fail "MCP_ENCRYPTION_KEY was not generated"
  grep -qx 'MCP_CONFIG_VERSION=1' "${config_path}" || fail "MCP_CONFIG_VERSION is missing"
  grep -qx "MCP_UPDATE_OFFERED=${update_offered}" "${config_path}" || fail "MCP_UPDATE_OFFERED is incorrect"
  for expected in "${expected_defaults[@]}"; do
    grep -qx "${expected}" "${config_path}" || fail "missing MCP default: ${expected%%=*}"
  done
  test "$(file_mode "${config_path}")" = 600 || fail "mailcow.conf mode is not 0600"
}

test_upgrade_generates_durable_config() {
  local case_dir="${TEST_DIR}/upgrade"
  local config_path="${case_dir}/mailcow.conf"
  local first_hash
  local second_hash

  mkdir -p "${case_dir}"
  cat > "${config_path}" <<'EOF'
MAILCOW_HOSTNAME=mail.example.test
COMPOSE_PROFILES=foo,bar
UNRELATED_OPTION=preserve-me
EOF
  chmod 0644 "${config_path}"

  mcp_prepare_config "${config_path}" upgrade
  assert_mcp_defaults "${config_path}" 0
  grep -qx 'COMPOSE_PROFILES=foo,bar' "${config_path}" || fail "existing profiles changed"
  grep -qx 'UNRELATED_OPTION=preserve-me' "${config_path}" || fail "unrelated configuration changed"
  first_hash="$(secret_hashes "${config_path}")"

  mcp_prepare_config "${config_path}" upgrade
  second_hash="$(secret_hashes "${config_path}")"
  test "${first_hash}" = "${second_hash}" || fail "migration changed existing secrets"
  pass "upgrade creates an idempotent disabled MCP configuration"
}

test_marker_with_missing_key_fails_without_mutation() {
  local case_dir="${TEST_DIR}/missing-key"
  local config_path="${case_dir}/mailcow.conf"
  local before_hash
  local error_output

  mkdir -p "${case_dir}"
  cat > "${config_path}" <<'EOF'
MCP_CONFIG_VERSION=1
MCP_DBPASS=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
MCP_UPDATE_OFFERED=0
COMPOSE_PROFILES=
EOF
  before_hash="$(sha256sum "${config_path}" | awk '{print $1}')"

  if error_output="$(mcp_prepare_config "${config_path}" upgrade 2>&1)"; then
    fail "marker with a missing encryption key unexpectedly succeeded"
  fi
  [[ "${error_output}" == *'MCP_ENCRYPTION_KEY must be set exactly once'* ]] || fail "missing encryption key did not reach MCP validation"
  [[ "${error_output}" != *'unbound variable'* ]] || fail "failed migration emitted a cleanup error"
  test "${before_hash}" = "$(sha256sum "${config_path}" | awk '{print $1}')" || fail "failed migration modified config"
  pass "marker with a missing key fails without mutation"
}

test_versioned_config_gets_missing_non_secret_defaults() {
  local case_dir="${TEST_DIR}/versioned-defaults"
  local config_path="${case_dir}/mailcow.conf"
  local before_hash

  mkdir -p "${case_dir}"
  cat > "${config_path}" <<'EOF'
MCP_CONFIG_VERSION=1
MCP_DBPASS=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
MCP_ENCRYPTION_KEY=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
COMPOSE_PROFILES=foo,bar
EOF

  before_hash="$(secret_hashes "${config_path}")"
  mcp_prepare_config "${config_path}" upgrade
  assert_mcp_defaults "${config_path}" 0
  test "${before_hash}" = "$(secret_hashes "${config_path}")" || fail "versioned default migration changed existing secrets"
  grep -qx 'COMPOSE_PROFILES=foo,bar' "${config_path}" || fail "versioned profiles changed"
  pass "versioned config gets missing non-secret defaults"
}

test_versioned_config_repairs_secret_file_permissions() {
  local case_dir="${TEST_DIR}/versioned-permissions"
  local config_path="${case_dir}/mailcow.conf"
  local before_hash

  mkdir -p "${case_dir}"
  printf 'MAILCOW_HOSTNAME=mail.example.test\n' > "${config_path}"
  mcp_prepare_config "${config_path}" upgrade
  before_hash="$(secret_hashes "${config_path}")"
  chmod 0644 "${config_path}"

  mcp_prepare_config "${config_path}" upgrade
  test "$(file_mode "${config_path}")" = 600 || fail "versioned config mode was not repaired to 0600"
  test "${before_hash}" = "$(secret_hashes "${config_path}")" || fail "permission repair changed existing secrets"

  chmod() { return 1; }
  if mcp_prepare_config "${config_path}" upgrade >/dev/null 2>&1; then
    unset -f chmod
    fail "failed permission repair unexpectedly succeeded"
  fi
  unset -f chmod
  pass "versioned config repairs secret file permissions"
}

test_profile_helpers_match_exact_tokens() {
  mcp_profile_contains 'foo,mcp,bar' mcp || fail "exact MCP token was not found"
  if mcp_profile_contains 'foo,mcp2,bar' mcp; then
    fail "partial profile token matched"
  fi
  test "$(mcp_profile_add '' mcp)" = 'mcp' || fail "empty profile list did not accept a token"
  test "$(mcp_profile_add 'foo,bar' mcp)" = 'foo,bar,mcp' || fail "profile token was not appended"
  test "$(mcp_profile_add 'foo,mcp,bar' mcp)" = 'foo,mcp,bar' || fail "existing profile token changed"
  test "$(mcp_profile_remove 'foo,mcp,bar' mcp)" = 'foo,bar' || fail "profile token was not removed"
  test "$(mcp_profile_remove 'mcp' mcp)" = '' || fail "single profile token was not removed"
  test "$(mcp_profile_remove 'foo,mcp2,bar' mcp)" = 'foo,mcp2,bar' || fail "partial profile token was removed"
  pass "profile helpers use exact comma-separated tokens"
}

test_interrupted_rename_leaves_existing_config_intact() {
  local case_dir="${TEST_DIR}/interrupted-rename"
  local config_path="${case_dir}/mailcow.conf"
  local before_hash

  mkdir -p "${case_dir}"
  cat > "${config_path}" <<'EOF'
MAILCOW_HOSTNAME=mail.example.test
EOF
  before_hash="$(sha256sum "${config_path}" | awk '{print $1}')"

  mv() { return 1; }
  if mcp_prepare_config "${config_path}" upgrade >/dev/null 2>&1; then
    unset -f mv
    fail "interrupted atomic rename unexpectedly succeeded"
  fi
  unset -f mv

  test "${before_hash}" = "$(sha256sum "${config_path}" | awk '{print $1}')" || fail "interrupted rename changed config"
  pass "interruption before atomic rename preserves the original config"
}

test_new_install_marks_offer_handled() {
  local case_dir="${TEST_DIR}/new-install"
  local config_path="${case_dir}/mailcow.conf"

  mkdir -p "${case_dir}"
  printf 'MAILCOW_HOSTNAME=mail.example.test\n' > "${config_path}"

  mcp_prepare_config "${config_path}" new
  assert_mcp_defaults "${config_path}" 1
  grep -qx 'COMPOSE_PROFILES=' "${config_path}" || fail "new install did not remain MCP-disabled"
  pass "new install marks the MCP offer handled and remains disabled"
}

test_generators_delegate_to_shared_mcp_migration() {
  grep -qx 'source _modules/scripts/mcp_config.sh' "${REPO_DIR}/generate_config.sh" || fail "new-install generator does not load MCP migration helper"
  grep -qx 'mcp_prepare_config mailcow.conf new || exit 1' "${REPO_DIR}/generate_config.sh" || fail "new-install generator does not prepare MCP config"
  grep -q 'source "${NEW_OPTIONS_DIR}/mcp_config.sh"' "${REPO_DIR}/_modules/scripts/new_options.sh" || fail "upgrade options do not load MCP migration helper"
  grep -qx '    mcp_prepare_config mailcow.conf upgrade || return 1' "${REPO_DIR}/_modules/scripts/new_options.sh" || fail "upgrade options do not prepare MCP config"
  pass "new and upgrade generators delegate to the shared MCP migration"
}

test_upgrade_generates_durable_config
test_marker_with_missing_key_fails_without_mutation
test_versioned_config_gets_missing_non_secret_defaults
test_versioned_config_repairs_secret_file_permissions
test_profile_helpers_match_exact_tokens
test_interrupted_rename_leaves_existing_config_intact
test_new_install_marks_offer_handled
test_generators_delegate_to_shared_mcp_migration
