#!/usr/bin/env bash

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MCP_SCRIPT="${REPO_DIR}/helper-scripts/mcp.sh"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "${TEST_DIR}"' EXIT

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_file_equals() {
  cmp -s "$1" "$2" || fail "$3"
}

assert_no_core_down() {
  if grep -Fq 'docker compose down' "$1"; then
    fail "an MCP lifecycle path called docker compose down"
  fi
}

write_config() {
  local path="$1"
  local profiles="$2"
  cat > "${path}" <<EOF
MAILCOW_HOSTNAME=mail.example.test
COMPOSE_PROJECT_NAME=mailcowdockerized
DBROOT=feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface
COMPOSE_PROFILES=${profiles}
MCP_UPDATE_OFFERED=0
MCP_DBNAME=mailcow_mcp
MCP_DBUSER=mailcow_mcp
MCP_DBPASS=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
MCP_ENCRYPTION_KEY=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
MCP_OAUTH_ALLOWED_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback
MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS=1
MCP_ATTACHMENT_MAX_BYTES=10485760
MCP_MESSAGE_MAX_BYTES=26214400
MCP_BASE64_UPLOAD_MAX_BYTES=1048576
MCP_UPLOAD_TTL_SECONDS=3600
MCP_ATTACHMENT_ALLOWED_TYPES=pdf,xlsx,csv,txt,png,jpg,jpeg
MCP_LOGIN_ATTEMPTS=5
MCP_LOGIN_WINDOW_SECONDS=900
MCP_REGISTRATIONS_PER_HOUR=10
MCP_REQUESTS_PER_MINUTE=120
MCP_SENDS_PER_MINUTE=10
MCP_RECIPIENTS_PER_HOUR=100
MCP_CONCURRENT_UPLOADS=5
MCP_AUDIT_RETENTION_DAYS=30
MCP_CONFIG_VERSION=1
MCP_ACTIVATION_LOCAL_VERIFY=0
EOF
  chmod 600 "${path}"
}

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

make_case() {
  local name="$1"
  local profiles="${2:-foo,bar}"
  local case_dir="${TEST_DIR}/${name}"

  mkdir -p "${case_dir}/helper-scripts" "${case_dir}/_modules/scripts" "${case_dir}/bin"
  cp "${MCP_SCRIPT}" "${case_dir}/helper-scripts/mcp.sh"
  cp "${REPO_DIR}/_modules/scripts/mcp_config.sh" "${case_dir}/_modules/scripts/mcp_config.sh"
  write_config "${case_dir}/mailcow.conf" "${profiles}"
  ln -s mailcow.conf "${case_dir}/.env"

  cat > "${case_dir}/bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
  printf '0\n'
else
  exec /usr/bin/id "$@"
fi
EOF

  cat > "${case_dir}/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -u

existing_app_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
existing_init_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
new_app_id=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
new_init_id=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
profiles="$(sed -n 's/^COMPOSE_PROFILES=//p' "${MCP_TEST_CONFIG}")"
printf 'profiles=%s|docker %s\n' "${profiles}" "$*" >> "${MCP_TEST_CALL_LOG}"

stage=""
case " $* " in
  *" compose --profile mcp config -q "*) stage=config ;;
  *" compose --profile mcp pull mcp-mailcow "*) stage=pull ;;
  *" compose up -d mysql-mailcow "*) stage=mysql ;;
  *" compose --profile mcp run --rm mcp-db-init node dist/db/init.js "*) stage=init ;;
  *" compose --profile mcp run --rm --no-deps mcp-mailcow node dist/db/migrations.js "*) stage=migration ;;
  *" compose --profile mcp up -d --no-deps mcp-mailcow "*) stage=app ;;
  *" compose up -d --no-deps --force-recreate nginx-mailcow "*) stage=nginx ;;
  *" compose --profile mcp stop mcp-mailcow "*) stage=stop ;;
  *" rm -f ${new_app_id} "*|*" rm -f ${new_init_id} "*) stage=remove ;;
  *" rm ${existing_app_id} "*) stage=purge-container ;;
  *" compose exec -T mysql-mailcow "*) stage=purge-db ;;
  *" volume rm labeled-mcp-volume "*) stage=purge-volume ;;
esac

if [[ -n "${stage}" ]]; then
  printf '%s\n' "${stage}" >> "${MCP_TEST_STAGE_LOG}"
fi

if [[ "${1:-}" == "compose" && "${2:-}" == "--profile" && "${3:-}" == "mcp" &&
      "${4:-}" == "ps" && "${5:-}" == "-aq" ]]; then
  inventory_phase=baseline
  test -s "${MCP_TEST_STAGE_LOG}" && inventory_phase=post
  case "${6:-}" in
    mcp-mailcow)
      if [[ "${MCP_TEST_CLEANUP_FAIL_STAGE:-}" == "${inventory_phase}-inventory-app" ]]; then
        exit 1
      fi
      if [[ ",${MCP_TEST_EXISTING:-}," == *",mcp-mailcow,"* ]]; then
        printf '%s\n' "${existing_app_id}"
      elif grep -qx 'app' "${MCP_TEST_STAGE_LOG}" 2>/dev/null; then
        printf '%s\n' "${new_app_id}"
      fi
      ;;
    mcp-db-init)
      if [[ "${MCP_TEST_CLEANUP_FAIL_STAGE:-}" == "${inventory_phase}-inventory-init" ]]; then
        exit 1
      fi
      if [[ ",${MCP_TEST_EXISTING:-}," == *",mcp-db-init,"* ]]; then
        printf '%s\n' "${existing_init_id}"
      elif grep -qx 'init' "${MCP_TEST_STAGE_LOG}" 2>/dev/null; then
        printf '%s\n' "${new_init_id}"
      fi
      ;;
  esac
fi

if [[ "${1:-}" == volume && "${2:-}" == ls ]]; then
  case "${MCP_TEST_VOLUME_STATE:-present}" in
    absent) exit 0 ;;
    list-error) exit 1 ;;
    multiple) printf 'labeled-mcp-volume\nother-mcp-volume\n' ;;
    *) printf 'labeled-mcp-volume\n' ;;
  esac
  exit 0
fi

if [[ "${1:-}" == volume && "${2:-}" == inspect ]]; then
  case "${MCP_TEST_VOLUME_STATE:-present}" in
    inspect-error) exit 1 ;;
    wrong-label) printf 'other-project|mcp-attachments-vol-1\n' ;;
    *) printf 'mailcowdockerized|mcp-attachments-vol-1\n' ;;
  esac
  exit 0
fi

if [[ "${1:-}" == inspect && "${2:-}" == "${existing_app_id}" ]]; then
  case "${MCP_TEST_APP_CONTAINER_STATE:-stopped}" in
    inspect-error) exit 1 ;;
    wrong-label) printf 'other-project|mcp-mailcow|false\n' ;;
    wrong-service) printf 'mailcowdockerized|other-service|false\n' ;;
    running) printf 'mailcowdockerized|mcp-mailcow|true\n' ;;
    *) printf 'mailcowdockerized|mcp-mailcow|false\n' ;;
  esac
  exit 0
fi

if [[ "${stage}" == purge-volume &&
      "${MCP_TEST_VOLUME_REJECT_REFERENCE:-n}" == y ]] &&
  ! grep -qx 'purge-container' "${MCP_TEST_STAGE_LOG}" 2>/dev/null; then
  exit 1
fi

if [[ "${stage}" == remove && "${MCP_TEST_CLEANUP_FAIL_STAGE:-}" == remove ]]; then
  exit 1
fi

if [[ -n "${stage}" && "${MCP_TEST_FAIL_STAGE:-}" == "${stage}" &&
      ! -e "${MCP_TEST_FAIL_MARKER}" ]]; then
  : > "${MCP_TEST_FAIL_MARKER}"
  exit 1
fi

if [[ -n "${MCP_TEST_SIGNAL_STAGE:-}" && "${stage}" == "${MCP_TEST_SIGNAL_STAGE}" ]]; then
  kill -TERM "${MCP_LIFECYCLE_PID}"
fi
EOF

  cat > "${case_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -u

printf 'curl %s\n' "$*" >> "${MCP_TEST_CALL_LOG}"
stage=discovery
[[ " $* " == *" -X POST "* && " $* " == *"/mcp "* ]] && stage=mcp-auth
printf '%s\n' "${stage}" >> "${MCP_TEST_STAGE_LOG}"

if [[ "${MCP_TEST_FAIL_STAGE:-}" == "${stage}" ]]; then
  exit 1
fi

output_file=/dev/null
header_file=
previous=
for argument in "$@"; do
  if [[ "${previous}" == --output ]]; then
    output_file="${argument}"
  elif [[ "${previous}" == --dump-header ]]; then
    header_file="${argument}"
  fi
  previous="${argument}"
done

url="${*: -1}"
hostname="$(sed -n 's/^MAILCOW_HOSTNAME=//p' "${MCP_TEST_CONFIG}")"
issuer="https://${hostname}"

if [[ "${url}" == *"/.well-known/oauth-authorization-server" ]]; then
  attempts=0
  test -f "${MCP_TEST_READINESS_COUNT}" && attempts="$(cat "${MCP_TEST_READINESS_COUNT}")"
  attempts=$((attempts + 1))
  printf '%s\n' "${attempts}" > "${MCP_TEST_READINESS_COUNT}"
  if (( attempts <= ${MCP_TEST_SLOW_ATTEMPTS:-0} )); then
    printf '{"error":"starting"}' > "${output_file}"
    printf '503'
    exit 0
  fi
  if [[ "${MCP_TEST_INVALID_RESPONSE:-}" == authorization-json ]]; then
    printf '{"issuer":"https://wrong.example.test"}' > "${output_file}"
  else
    printf '{"issuer":"%s"}' "${issuer}" > "${output_file}"
  fi
  printf '200'
elif [[ "${url}" == *"/.well-known/oauth-protected-resource/mcp" ]]; then
  attempts="$(cat "${MCP_TEST_READINESS_COUNT}")"
  if (( attempts <= ${MCP_TEST_PROTECTED_SLOW_ATTEMPTS:-0} )); then
    printf '{"error":"starting"}' > "${output_file}"
    printf '503'
    exit 0
  fi
  if [[ "${MCP_TEST_INVALID_RESPONSE:-}" == protected-json ]]; then
    printf '{"resource":"https://wrong.example.test/mcp","authorization_servers":[]}' > "${output_file}"
  else
    printf '{"resource":"%s/mcp","authorization_servers":["%s"]}' "${issuer}" "${issuer}" > "${output_file}"
  fi
  printf '200'
else
  attempts="$(cat "${MCP_TEST_READINESS_COUNT}")"
  if (( attempts <= ${MCP_TEST_CHALLENGE_SLOW_ATTEMPTS:-0} )); then
    test -n "${header_file}" && printf 'HTTP/2 503\r\n\r\n' > "${header_file}"
    printf '503'
    exit 0
  fi
  if [[ -n "${header_file}" ]]; then
    if [[ "${MCP_TEST_INVALID_RESPONSE:-}" == challenge ]]; then
      printf 'HTTP/2 401\r\nWWW-Authenticate: Bearer\r\n\r\n' > "${header_file}"
    else
      printf 'HTTP/2 401\r\nWWW-Authenticate: Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"\r\n\r\n' \
        "${issuer}" > "${header_file}"
    fi
  fi
  printf '401'
fi
EOF

  cat > "${case_dir}/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

  cat > "${case_dir}/bin/mv" <<'EOF'
#!/usr/bin/env bash
set -u
source_path="${1:-}"
if [[ "${source_path}" == -- ]]; then
  source_path="${2:-}"
fi
/bin/mv "$@"
source_name="$(basename "${source_path}")"
if [[ "${MCP_TEST_SIGNAL_STAGE:-}" == config-prepare &&
      "${source_name}" == .mailcow.conf.mcp.* &&
      "${source_name}" != .mailcow.conf.mcp-state.* &&
      ! -e "${MCP_TEST_SIGNAL_MARKER}" ]]; then
  : > "${MCP_TEST_SIGNAL_MARKER}"
  kill -TERM "${MCP_LIFECYCLE_PID}"
fi
EOF

  cat > "${case_dir}/rollback-debug-hook" <<'EOF'
set -T
mcp_test_rollback_debug_hook() {
  local observed_command="${BASH_COMMAND}"
  local observed_function="${FUNCNAME[1]:-}"

  [[ "${MCP_TEST_DEBUG_HOOK_RUNNING:-n}" == n ]] || return
  MCP_TEST_DEBUG_HOOK_RUNNING=y

  if [[ "${observed_function}" == mcp_rollback_transaction &&
        "${MCP_TEST_SIGNAL_STAGE:-}" == rollback-setup &&
        "${MCP_TRANSACTION_ROLLING_BACK:-n}" == y &&
        ! -e "${MCP_TEST_SIGNAL_MARKER}" ]]; then
    : > "${MCP_TEST_SIGNAL_MARKER}"
    printf 'setup active=%s rolling=%s\n' \
      "${MCP_TRANSACTION_ACTIVE:-unset}" \
      "${MCP_TRANSACTION_ROLLING_BACK:-unset}" >> "${MCP_TEST_ROLLBACK_HOOK_LOG}"
    kill -TERM "${MCP_LIFECYCLE_PID}"
  fi

  if [[ "${observed_function}" == mcp_rollback_transaction &&
        "${observed_command}" == "MCP_TRANSACTION_ACTIVE=n" ]]; then
    printf 'result active=%s rolling=%s result=%s signal=%s\n' \
      "${MCP_TRANSACTION_ACTIVE:-unset}" \
      "${MCP_TRANSACTION_ROLLING_BACK:-unset}" \
      "${result_status:-unset}" \
      "${signal_status:-unset}" >> "${MCP_TEST_ROLLBACK_HOOK_LOG}"
  fi

  MCP_TEST_DEBUG_HOOK_RUNNING=n
}
trap mcp_test_rollback_debug_hook DEBUG
EOF

  chmod +x "${case_dir}/helper-scripts/mcp.sh" "${case_dir}/bin/id" \
    "${case_dir}/bin/docker" "${case_dir}/bin/curl" "${case_dir}/bin/sleep" \
    "${case_dir}/bin/mv"
  printf '%s\n' "${case_dir}"
}

run_mcp() {
  local case_dir="$1"
  shift
  (
    cd "${case_dir}"
    BASH_ENV="${MCP_TEST_BASH_ENV:-}" \
      PATH="${case_dir}/bin:${PATH}" \
      MCP_TEST_CONFIG="${case_dir}/mailcow.conf" \
      MCP_TEST_CALL_LOG="${case_dir}/calls.log" \
      MCP_TEST_STAGE_LOG="${case_dir}/stages.log" \
      MCP_TEST_FAIL_MARKER="${case_dir}/failed-once" \
      MCP_TEST_FAIL_STAGE="${MCP_TEST_FAIL_STAGE:-}" \
      MCP_TEST_CLEANUP_FAIL_STAGE="${MCP_TEST_CLEANUP_FAIL_STAGE:-}" \
      MCP_TEST_EXISTING="${MCP_TEST_EXISTING:-}" \
      MCP_TEST_SIGNAL_STAGE="${MCP_TEST_SIGNAL_STAGE:-}" \
      MCP_TEST_INVALID_RESPONSE="${MCP_TEST_INVALID_RESPONSE:-}" \
      MCP_TEST_SLOW_ATTEMPTS="${MCP_TEST_SLOW_ATTEMPTS:-0}" \
      MCP_TEST_PROTECTED_SLOW_ATTEMPTS="${MCP_TEST_PROTECTED_SLOW_ATTEMPTS:-0}" \
      MCP_TEST_CHALLENGE_SLOW_ATTEMPTS="${MCP_TEST_CHALLENGE_SLOW_ATTEMPTS:-0}" \
      MCP_TEST_READINESS_COUNT="${case_dir}/readiness-count" \
      MCP_TEST_SIGNAL_MARKER="${case_dir}/signal-once" \
      MCP_TEST_ROLLBACK_HOOK_LOG="${case_dir}/rollback-hook.log" \
      MCP_TEST_VOLUME_STATE="${MCP_TEST_VOLUME_STATE:-present}" \
      MCP_TEST_APP_CONTAINER_STATE="${MCP_TEST_APP_CONTAINER_STATE:-stopped}" \
      MCP_TEST_VOLUME_REJECT_REFERENCE="${MCP_TEST_VOLUME_REJECT_REFERENCE:-n}" \
      bash "${case_dir}/helper-scripts/mcp.sh" "$@"
  )
}

test_enable_success_and_idempotence() {
  local case_dir
  local calls_before
  case_dir="$(make_case enable-success)"

  run_mcp "${case_dir}" enable >/dev/null

  grep -qx 'COMPOSE_PROFILES=foo,bar,mcp' "${case_dir}/mailcow.conf" ||
    fail "enable did not preserve unrelated profile tokens"
  grep -qx 'MCP_UPDATE_OFFERED=1' "${case_dir}/mailcow.conf" ||
    fail "enable did not record the offer as handled"
  test "$(stat -f '%Lp' "${case_dir}/mailcow.conf.mcp.bak")" = 600 ||
    fail "enable backup was not mode 0600"
  grep -qx 'COMPOSE_PROFILES=foo,bar' "${case_dir}/mailcow.conf.mcp.bak" ||
    fail "enable backup did not capture the prior configuration"
  [[ "$(tr '\n' ' ' < "${case_dir}/stages.log")" == "config pull mysql init migration app nginx discovery discovery mcp-auth " ]] ||
    fail "enable did not execute the required activation sequence"
  assert_no_core_down "${case_dir}/calls.log"

  calls_before="$(wc -l < "${case_dir}/calls.log")"
  run_mcp "${case_dir}" enable >/dev/null
  test "$(wc -l < "${case_dir}/calls.log")" = "${calls_before}" ||
    fail "idempotent enable repeated Docker or network side effects"
  pass "enable is ordered, profile-safe, and idempotent"
}

test_already_enabled_enable_migrates_defaults_without_side_effects() {
  local case_dir
  local malformed_dir
  local before_secret_hash

  case_dir="$(make_case enabled-default-migration foo,mcp,bar)"
  grep -v '^MCP_AUDIT_RETENTION_DAYS=' "${case_dir}/mailcow.conf" \
    > "${case_dir}/mailcow.conf.missing-default"
  mv "${case_dir}/mailcow.conf.missing-default" "${case_dir}/mailcow.conf"
  chmod 600 "${case_dir}/mailcow.conf"
  before_secret_hash="$(grep -E '^MCP_(DBPASS|ENCRYPTION_KEY)=' \
    "${case_dir}/mailcow.conf" | sha256sum | awk '{print $1}')"

  run_mcp "${case_dir}" enable >/dev/null

  grep -qx 'MCP_AUDIT_RETENTION_DAYS=30' "${case_dir}/mailcow.conf" ||
    fail "already-enabled enable did not append a missing non-secret default"
  grep -qx 'COMPOSE_PROFILES=foo,mcp,bar' "${case_dir}/mailcow.conf" ||
    fail "already-enabled default migration changed profile state"
  test "${before_secret_hash}" = "$(grep -E '^MCP_(DBPASS|ENCRYPTION_KEY)=' \
    "${case_dir}/mailcow.conf" | sha256sum | awk '{print $1}')" ||
    fail "already-enabled default migration changed existing secrets"
  test ! -s "${case_dir}/calls.log" 2>/dev/null ||
    fail "already-enabled default migration caused Docker or network side effects"

  malformed_dir="$(make_case enabled-malformed-secret foo,mcp,bar)"
  sed 's/^MCP_DBPASS=.*/MCP_DBPASS=invalid/' "${malformed_dir}/mailcow.conf" \
    > "${malformed_dir}/mailcow.conf.invalid"
  mv "${malformed_dir}/mailcow.conf.invalid" "${malformed_dir}/mailcow.conf"
  chmod 600 "${malformed_dir}/mailcow.conf"
  cp "${malformed_dir}/mailcow.conf" "${malformed_dir}/before.conf"

  if run_mcp "${malformed_dir}" enable >/dev/null 2>&1; then
    fail "already-enabled enable accepted a malformed versioned secret"
  fi
  assert_file_equals "${malformed_dir}/before.conf" "${malformed_dir}/mailcow.conf" \
    "failed already-enabled migration changed malformed config bytes"
  test ! -s "${malformed_dir}/calls.log" 2>/dev/null ||
    fail "failed already-enabled migration caused Docker or network side effects"
  pass "already-enabled enable atomically migrates defaults without side effects"
}

test_enable_rolls_back_each_failure() {
  local stage
  local case_dir
  local final_nginx
  local removed_calls

  for stage in config pull init migration app nginx discovery; do
    case_dir="$(make_case "enable-failure-${stage}")"
    cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

    if MCP_TEST_FAIL_STAGE="${stage}" run_mcp "${case_dir}" enable >/dev/null 2>&1; then
      fail "enable unexpectedly succeeded when ${stage} failed"
    fi

    assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
      "enable did not restore exact config bytes after ${stage} failure"
    final_nginx="$(grep 'force-recreate nginx-mailcow' "${case_dir}/calls.log" | tail -1)"
    [[ "${final_nginx}" == profiles=foo,bar\|* ]] ||
      fail "rollback did not recreate nginx with MCP disabled after ${stage} failure"
    removed_calls="$(grep -Ec '\|docker rm -f (cccc|dddd)' "${case_dir}/calls.log" || true)"
    if [[ "${stage}" == config || "${stage}" == pull ]]; then
      test "${removed_calls}" = 0 ||
        fail "rollback removed a container before MCP created one at ${stage}"
    else
      test "${removed_calls}" -ge 1 ||
        fail "rollback did not remove newly created MCP containers after ${stage} failure"
    fi
    assert_no_core_down "${case_dir}/calls.log"
  done
  pass "every activation failure restores bytes and leaves core nginx MCP-disabled"
}

test_rollback_preserves_preexisting_mcp_container() {
  local case_dir
  case_dir="$(make_case preserve-existing)"
  cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

  if MCP_TEST_EXISTING=mcp-db-init MCP_TEST_FAIL_STAGE=app \
    run_mcp "${case_dir}" enable >/dev/null 2>&1; then
    fail "enable unexpectedly succeeded with injected app failure"
  fi

  grep -q '|docker rm -f cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "${case_dir}/calls.log" ||
    fail "rollback did not remove the newly created application container"
  if grep -q '|docker rm -f bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "${case_dir}/calls.log"; then
    fail "rollback removed a pre-existing MCP initializer container"
  fi
  assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
    "rollback changed config while preserving a pre-existing container"
  pass "rollback removes only newly created MCP containers"
}

test_baseline_inventory_failure_aborts_without_mutation() {
  local stage
  local case_dir

  for stage in baseline-inventory-app baseline-inventory-init; do
    case_dir="$(make_case "${stage}")"
    cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

    if MCP_TEST_EXISTING=mcp-mailcow,mcp-db-init MCP_TEST_CLEANUP_FAIL_STAGE="${stage}" \
      run_mcp "${case_dir}" enable >/dev/null 2>&1; then
      fail "enable continued after ${stage} failed"
    fi

    assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
      "${stage} changed configuration bytes"
    if grep -q '|docker rm -f ' "${case_dir}/calls.log"; then
      fail "${stage} removed a pre-existing MCP container"
    fi
    if grep -q '^profiles=.*mcp|docker compose --profile mcp config -q' "${case_dir}/calls.log"; then
      fail "${stage} continued into activation"
    fi
  done
  pass "failed baseline inventory aborts before mutation or container removal"
}

test_term_during_activation_runs_transaction_rollback() {
  local case_dir
  local status
  local final_nginx
  case_dir="$(make_case signal-term)"
  cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

  status=0
  MCP_TEST_SIGNAL_STAGE=app run_mcp "${case_dir}" enable >/dev/null 2>&1 || status=$?

  test "${status}" = 143 || fail "TERM during activation returned ${status}, expected 143"
  assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
    "TERM during activation did not restore exact config bytes"
  grep -q '|docker rm -f cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
    "${case_dir}/calls.log" || fail "TERM rollback did not remove the new MCP app container"
  final_nginx="$(grep 'force-recreate nginx-mailcow' "${case_dir}/calls.log" | tail -1)"
  [[ "${final_nginx}" == profiles=foo,bar\|* ]] ||
    fail "TERM rollback did not recreate nginx with MCP disabled"
  test ! -d "${case_dir}/.mcp-lifecycle.lock" ||
    fail "TERM rollback left the lifecycle lock behind"
  pass "TERM during an active transaction performs full rollback"
}

test_term_during_config_preparation_restores_exact_backup() {
  local case_dir
  local status
  local final_nginx
  case_dir="$(make_case signal-config-prepare)"
  cat > "${case_dir}/mailcow.conf" <<'EOF'
MAILCOW_HOSTNAME=mail.example.test
COMPOSE_PROJECT_NAME=mailcowdockerized
DBROOT=feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface
COMPOSE_PROFILES=foo,bar
EOF
  chmod 600 "${case_dir}/mailcow.conf"
  cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

  status=0
  MCP_TEST_SIGNAL_STAGE=config-prepare run_mcp "${case_dir}" enable >/dev/null 2>&1 ||
    status=$?

  test "${status}" = 143 ||
    fail "TERM during config preparation returned ${status}, expected 143"
  assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
    "TERM during config preparation did not restore exact pre-migration bytes"
  final_nginx="$(grep 'force-recreate nginx-mailcow' "${case_dir}/calls.log" | tail -1)"
  [[ "${final_nginx}" == profiles=foo,bar\|* ]] ||
    fail "config-preparation TERM did not complete disabled nginx recreation"
  test ! -d "${case_dir}/.mcp-lifecycle.lock" ||
    fail "config-preparation TERM left the lifecycle lock behind"
  pass "TERM during config preparation restores backup and completes rollback"
}

test_term_during_rollback_cleanup_finishes_rollback() {
  local case_dir
  local status
  local final_nginx
  case_dir="$(make_case signal-rollback-cleanup)"
  cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

  status=0
  MCP_TEST_FAIL_STAGE=app MCP_TEST_SIGNAL_STAGE=remove \
    run_mcp "${case_dir}" enable >/dev/null 2>&1 || status=$?

  test "${status}" = 143 ||
    fail "TERM during rollback cleanup returned ${status}, expected 143"
  assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
    "TERM during rollback cleanup interrupted exact config restoration"
  grep -q '|docker rm -f cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
    "${case_dir}/calls.log" || fail "rollback cleanup TERM missed the new MCP app"
  grep -q '|docker rm -f dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
    "${case_dir}/calls.log" || fail "rollback cleanup TERM interrupted initializer cleanup"
  final_nginx="$(grep 'force-recreate nginx-mailcow' "${case_dir}/calls.log" | tail -1)"
  [[ "${final_nginx}" == profiles=foo,bar\|* ]] ||
    fail "rollback cleanup TERM interrupted disabled nginx recreation"
  test ! -d "${case_dir}/.mcp-lifecycle.lock" ||
    fail "rollback cleanup TERM left the lifecycle lock behind"
  pass "TERM during rollback cleanup is deferred until rollback completes"
}

test_term_during_rollback_setup_cannot_bypass_rollback() {
  local case_dir
  local status
  local final_nginx
  case_dir="$(make_case signal-rollback-setup)"
  cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"

  status=0
  MCP_TEST_BASH_ENV="${case_dir}/rollback-debug-hook" \
    MCP_TEST_FAIL_STAGE=app MCP_TEST_SIGNAL_STAGE=rollback-setup \
    run_mcp "${case_dir}" enable >/dev/null 2>&1 || status=$?

  test "${status}" = 143 ||
    fail "TERM during rollback setup returned ${status}, expected 143"
  assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
    "TERM during rollback setup bypassed exact config restoration"
  grep -q '|docker rm -f cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
    "${case_dir}/calls.log" || fail "rollback-setup TERM missed the new MCP app"
  grep -q '|docker rm -f dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' \
    "${case_dir}/calls.log" || fail "rollback-setup TERM missed the new initializer"
  final_nginx="$(grep 'force-recreate nginx-mailcow' "${case_dir}/calls.log" | tail -1)"
  [[ "${final_nginx}" == profiles=foo,bar\|* ]] ||
    fail "rollback-setup TERM bypassed disabled nginx recreation"
  grep -qx 'result active=y rolling=y result=143 signal=143' \
    "${case_dir}/rollback-hook.log" ||
    fail "transaction was disarmed before rollback result collection completed"
  test ! -d "${case_dir}/.mcp-lifecycle.lock" ||
    fail "rollback-setup TERM left the lifecycle lock behind"
  pass "TERM during rollback setup cannot bypass an armed transaction"
}

test_rollback_reports_inventory_and_removal_failures() {
  local stage
  local case_dir
  local output
  local final_nginx

  for stage in post-inventory-app remove; do
    case_dir="$(make_case "cleanup-${stage}")"
    cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"
    if output="$(MCP_TEST_FAIL_STAGE=app MCP_TEST_CLEANUP_FAIL_STAGE="${stage}" \
      run_mcp "${case_dir}" enable 2>&1)"; then
      fail "activation unexpectedly succeeded with ${stage} cleanup failure"
    fi
    [[ "${output}" == *"rollback cleanup failed"* ]] ||
      fail "${stage} cleanup failure was not reported"
    assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
      "${stage} cleanup failure prevented exact config restoration"
    final_nginx="$(grep 'force-recreate nginx-mailcow' "${case_dir}/calls.log" | tail -1)"
    [[ "${final_nginx}" == profiles=foo,bar\|* ]] ||
      fail "${stage} cleanup failure prevented disabled nginx recreation"
  done
  pass "rollback reports cleanup failures after restoring config and nginx"
}

test_https_verification_retries_and_validates_metadata() {
  local case_dir
  local invalid
  local staged
  local final_nginx

  case_dir="$(make_case slow-readiness)"
  MCP_TEST_SLOW_ATTEMPTS=2 run_mcp "${case_dir}" enable >/dev/null
  test "$(cat "${case_dir}/readiness-count")" = 3 ||
    fail "HTTPS verification did not retry bounded readiness until success"
  grep -q 'curl --connect-timeout 5 --max-time 15' "${case_dir}/calls.log" ||
    fail "HTTPS verification omitted curl connect/overall timeouts"

  for staged in protected challenge; do
    case_dir="$(make_case "staged-${staged}-readiness")"
    if [[ "${staged}" == protected ]]; then
      MCP_TEST_PROTECTED_SLOW_ATTEMPTS=2 run_mcp "${case_dir}" enable >/dev/null
    else
      MCP_TEST_CHALLENGE_SLOW_ATTEMPTS=2 run_mcp "${case_dir}" enable >/dev/null
    fi
    test "$(cat "${case_dir}/readiness-count")" = 3 ||
      fail "${staged} readiness did not restart the complete HTTPS contract"
    grep -qx 'COMPOSE_PROFILES=foo,bar,mcp' "${case_dir}/mailcow.conf" ||
      fail "${staged} staged readiness did not complete activation"
  done

  for invalid in authorization-json protected-json challenge; do
    case_dir="$(make_case "invalid-${invalid}")"
    cp "${case_dir}/mailcow.conf" "${case_dir}/before.conf"
    if MCP_TEST_INVALID_RESPONSE="${invalid}" run_mcp "${case_dir}" enable >/dev/null 2>&1; then
      fail "HTTPS verification accepted invalid ${invalid}"
    fi
    assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
      "invalid ${invalid} did not roll back exact config bytes"
    final_nginx="$(grep 'force-recreate nginx-mailcow' "${case_dir}/calls.log" | tail -1)"
    [[ "${final_nginx}" == profiles=foo,bar\|* ]] ||
      fail "invalid ${invalid} did not recreate disabled nginx"
    test "$(cat "${case_dir}/readiness-count")" = 6 ||
      fail "persistent invalid ${invalid} did not exhaust bounded full-contract attempts"
  done
  pass "HTTPS verification retries and validates discovery URLs and challenge"
}

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

test_disable_is_idempotent_and_preserves_data_configuration() {
  local case_dir
  local before_without_profiles
  local after_without_profiles
  local calls_before
  case_dir="$(make_case disable foo,mcp,bar)"

  grep -v '^COMPOSE_PROFILES=' "${case_dir}/mailcow.conf" > "${case_dir}/before-without-profiles"
  run_mcp "${case_dir}" disable >/dev/null
  grep -v '^COMPOSE_PROFILES=' "${case_dir}/mailcow.conf" > "${case_dir}/after-without-profiles"

  grep -qx 'COMPOSE_PROFILES=foo,bar' "${case_dir}/mailcow.conf" ||
    fail "disable removed or changed an unrelated profile"
  assert_file_equals "${case_dir}/before-without-profiles" "${case_dir}/after-without-profiles" \
    "disable changed secrets or persistent MCP settings"
  if grep -Eq 'purge-db|purge-volume|volume rm' "${case_dir}/calls.log"; then
    fail "ordinary disable removed persistent MCP data"
  fi
  assert_no_core_down "${case_dir}/calls.log"

  calls_before="$(wc -l < "${case_dir}/calls.log")"
  run_mcp "${case_dir}" disable >/dev/null
  test "$(wc -l < "${case_dir}/calls.log")" = "${calls_before}" ||
    fail "idempotent disable repeated Docker side effects"
  pass "disable is idempotent and preserves secrets, database, and volume"
}

test_status_retry_and_purge_guards() {
  local case_dir
  local failure_case
  local volume_case
  local volume_state
  local output
  case_dir="$(make_case commands foo,bar)"

  output="$(run_mcp "${case_dir}" status)"
  [[ "${output}" == *"disabled"* ]] || fail "status did not report the disabled state"

  if printf 'PURGE mailcow-mcp\n' | run_mcp "${case_dir}" purge >/dev/null 2>&1; then
    fail "purge accepted an inexact confirmation"
  fi
  test ! -e "${case_dir}/calls.log" || test ! -s "${case_dir}/calls.log" ||
    fail "rejected purge caused Docker side effects"

  printf 'PURGE mailcow_mcp\n' | run_mcp "${case_dir}" purge >/dev/null
  grep -qx 'purge-db' "${case_dir}/stages.log" ||
    fail "confirmed purge did not remove the dedicated database"
  grep -qx 'purge-volume' "${case_dir}/stages.log" ||
    fail "confirmed purge did not remove the dedicated attachment volume"
  grep -q '|docker volume rm labeled-mcp-volume' "${case_dir}/calls.log" ||
    fail "purge did not remove the exact Compose-labeled MCP volume"
  assert_no_core_down "${case_dir}/calls.log"

  volume_case="$(make_case purge-volume-absent foo,bar)"
  printf 'PURGE mailcow_mcp\n' |
    MCP_TEST_VOLUME_STATE=absent run_mcp "${volume_case}" purge >/dev/null ||
    fail "purge did not accept a truly absent MCP volume"
  if grep -q '|docker volume rm ' "${volume_case}/calls.log"; then
    fail "purge tried to remove a volume when the labeled MCP volume was absent"
  fi

  for volume_state in inspect-error wrong-label; do
    volume_case="$(make_case "purge-${volume_state}" foo,bar)"
    if printf 'PURGE mailcow_mcp\n' |
      MCP_TEST_VOLUME_STATE="${volume_state}" run_mcp "${volume_case}" purge >/dev/null 2>&1; then
      fail "purge accepted MCP volume state ${volume_state}"
    fi
    if grep -q 'compose exec -T mysql-mailcow' "${volume_case}/calls.log"; then
      fail "purge dropped the database before validating volume state ${volume_state}"
    fi
  done

  failure_case="$(make_case purge-volume-failure foo,bar)"
  if printf 'PURGE mailcow_mcp\n' |
    MCP_TEST_FAIL_STAGE=purge-volume run_mcp "${failure_case}" purge >/dev/null 2>&1; then
    fail "purge reported success after attachment-volume removal failed"
  fi

  write_config "${case_dir}/mailcow.conf" foo,mcp,bar
  : > "${case_dir}/calls.log"
  : > "${case_dir}/stages.log"
  run_mcp "${case_dir}" retry >/dev/null
  [[ "$(tr '\n' ' ' < "${case_dir}/stages.log")" == "config pull mysql init migration app nginx discovery discovery mcp-auth " ]] ||
    fail "retry did not re-run the activation sequence"
  grep -qx 'COMPOSE_PROFILES=foo,mcp,bar' "${case_dir}/mailcow.conf" ||
    fail "retry changed the enabled profile set"
  pass "status, retry, and exact purge confirmation enforce their contracts"
}

test_inherited_profile_is_not_forwarded_to_compose() {
  local case_dir
  case_dir="$(make_case inherited-profile foo,bar)"

  COMPOSE_PROFILES=host-override run_mcp "${case_dir}" enable >/dev/null

  if grep -q 'profiles=host-override' "${case_dir}/calls.log"; then
    fail "an inherited COMPOSE_PROFILES value reached Docker Compose"
  fi
  grep -q '^profiles=foo,bar,mcp|docker compose' "${case_dir}/calls.log" ||
    fail "Compose did not observe the authoritative mailcow.conf profile"
  pass "inherited COMPOSE_PROFILES cannot override mailcow.conf"
}

test_purge_requires_disabled_state() {
  local case_dir
  case_dir="$(make_case purge-enabled mcp)"

  if printf 'PURGE mailcow_mcp\n' | run_mcp "${case_dir}" purge >/dev/null 2>&1; then
    fail "purge succeeded while MCP was enabled"
  fi
  test ! -e "${case_dir}/calls.log" || test ! -s "${case_dir}/calls.log" ||
    fail "enabled-state purge caused Docker side effects"
  pass "purge requires MCP to be disabled"
}

test_purge_removes_validated_stopped_app_before_data() {
  local app_state
  local case_dir

  case_dir="$(make_case purge-stopped-app foo,bar)"
  printf 'PURGE mailcow_mcp\n' |
    MCP_TEST_EXISTING=mcp-mailcow \
    MCP_TEST_VOLUME_REJECT_REFERENCE=y \
    run_mcp "${case_dir}" purge >/dev/null ||
    fail "purge did not remove the stopped MCP application reference"
  [[ "$(tr '\n' ' ' < "${case_dir}/stages.log")" == \
    "purge-container purge-db purge-volume " ]] ||
    fail "purge did not remove the stopped application before database and volume data"
  grep -q '|docker rm aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$' \
    "${case_dir}/calls.log" ||
    fail "purge did not remove the exact Compose-owned MCP application container"

  for app_state in running wrong-label wrong-service inspect-error; do
    case_dir="$(make_case "purge-app-${app_state}" foo,bar)"
    if printf 'PURGE mailcow_mcp\n' |
      MCP_TEST_EXISTING=mcp-mailcow \
      MCP_TEST_APP_CONTAINER_STATE="${app_state}" \
      run_mcp "${case_dir}" purge >/dev/null 2>&1; then
      fail "purge accepted MCP application container state ${app_state}"
    fi
    if grep -Eq '\|docker (rm |compose exec -T mysql-mailcow|volume rm )' \
      "${case_dir}/calls.log"; then
      fail "purge removed container or data for MCP application state ${app_state}"
    fi
  done
  pass "purge removes only a validated stopped Compose application before data"
}

test_update_offer_never_activates_unattended_or_skip_start() {
  local mode
  local case_dir
  local output

  for mode in force skip-start; do
    case_dir="${TEST_DIR}/offer-${mode}"
    mkdir -p "${case_dir}/helper-scripts"
    write_config "${case_dir}/mailcow.conf" foo,bar
    sed -i '' 's/^MCP_UPDATE_OFFERED=.*/MCP_UPDATE_OFFERED=0/' "${case_dir}/mailcow.conf"
    cat > "${case_dir}/helper-scripts/mcp.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${MCP_OFFER_ENABLE_LOG}"
EOF
    chmod +x "${case_dir}/helper-scripts/mcp.sh"

    (
      source "${REPO_DIR}/_modules/scripts/mcp_config.sh"
      source "${REPO_DIR}/_modules/scripts/core.sh"
      SCRIPT_DIR="${case_dir}"
      MAILCOW_CONF="${case_dir}/mailcow.conf"
      MCP_OFFER_ENABLE_LOG="${case_dir}/enable.log"
      export MCP_OFFER_ENABLE_LOG
      FORCE=
      SKIP_START=
      if [[ "${mode}" == force ]]; then
        FORCE=y
      else
        SKIP_START=y
      fi
      umask 0022
      mcp_update_offer >/dev/null
      test "$(umask)" = 0022
    ) || fail "update offer failed in ${mode} mode"

    grep -qx 'MCP_UPDATE_OFFERED=1' "${case_dir}/mailcow.conf" ||
      fail "${mode} update did not atomically record the offer as handled"
    test ! -s "${case_dir}/enable.log" ||
      fail "${mode} update invoked MCP enable"
  done

  case_dir="${TEST_DIR}/offer-already-enabled"
  mkdir -p "${case_dir}/helper-scripts"
  write_config "${case_dir}/mailcow.conf" foo,mcp,bar
  cat > "${case_dir}/helper-scripts/mcp.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${MCP_OFFER_ENABLE_LOG}"
EOF
  chmod +x "${case_dir}/helper-scripts/mcp.sh"
  output="$(
    source "${REPO_DIR}/_modules/scripts/mcp_config.sh"
    source "${REPO_DIR}/_modules/scripts/core.sh"
    SCRIPT_DIR="${case_dir}"
    MAILCOW_CONF="${case_dir}/mailcow.conf"
    MCP_OFFER_ENABLE_LOG="${case_dir}/enable.log"
    export MCP_OFFER_ENABLE_LOG
    FORCE=y
    SKIP_START=
    mcp_update_offer
  )" || fail "update offer failed for an already-enabled installation"
  [[ "${output}" == *"already enabled"* ]] ||
    fail "update offer reported an already-enabled installation as disabled"
  test ! -s "${case_dir}/enable.log" ||
    fail "update offer reactivated an already-enabled installation"
  pass "force and skip-start updates never activate MCP"
}

test_update_runtime_preflight_and_post_merge_validation() {
  local case_dir="${TEST_DIR}/update-runtime"
  local mock_bin="${case_dir}/bin"
  local update_log="${case_dir}/update.log"
  local candidate_failure_dir="${TEST_DIR}/update-candidate-validation-failure"
  local damaged_config_dir="${TEST_DIR}/update-damaged-disabled-config"
  local mcp_failure_dir="${TEST_DIR}/update-mcp-failure"
  local core_failure_dir="${TEST_DIR}/update-core-failure"
  local update_status
  local config_calls

  mkdir -p "${mock_bin}" "${case_dir}/data/assets/ssl-example" \
    "${case_dir}/data/assets/ssl" "${case_dir}/data/web/inc" \
    "${case_dir}/data/conf/nginx"
  cp -R "${REPO_DIR}/_modules" "${case_dir}/_modules"
  cp "${REPO_DIR}/update.sh" "${case_dir}/update.sh"
  cp "${REPO_DIR}/docker-compose.yml" "${case_dir}/docker-compose.yml"
  cat > "${case_dir}/mailcow.conf" <<'EOF'
MAILCOW_HOSTNAME=mail.example.test
COMPOSE_PROJECT_NAME=mailcowdockerized
DBROOT=feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface
IPV4_NETWORK=172.22.1
ENABLE_IPV6=false
COMPOSE_PROFILES=foo,bar
EOF
  chmod 600 "${case_dir}/mailcow.conf"
  ln -s mailcow.conf "${case_dir}/.env"
  mkdir -p "${case_dir}/helper-scripts"
  cat > "${case_dir}/helper-scripts/mcp.sh" <<'EOF'
#!/usr/bin/env bash
printf 'MCP-LIFECYCLE %s\n' "$*" >> "${MCP_UPDATE_TEST_LOG}"
EOF
  chmod +x "${case_dir}/helper-scripts/mcp.sh"

  cat > "${mock_bin}/docker" <<'EOF'
#!/usr/bin/env bash
set -u
if [[ "${1:-}" == version ]]; then
  printf '28.0.0\n'
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == version ]]; then
  printf '2.30.0\n'
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == config && "${3:-}" == -q ]]; then
  marker="$(sed -n 's/^MCP_CONFIG_VERSION=//p' mailcow.conf)"
  printf 'CONFIG-Q marker=%s inherited=%s\n' "${marker:-missing}" "${COMPOSE_PROFILES-unset}" >> "${MCP_UPDATE_TEST_LOG}"
  config_calls="$(grep -c '^CONFIG-Q ' "${MCP_UPDATE_TEST_LOG}" || true)"
  if [[ "${MCP_UPDATE_FAIL_MODE:-}" == candidate-config &&
        "${config_calls}" -ge 2 ]]; then
    exit 1
  fi
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == config && "${3:-}" == --services ]]; then
  printf '%s\n' mysql-mailcow nginx-mailcow postfix-mailcow mcp-db-init mcp-mailcow
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == config ]]; then
  printf 'name: test\nnetworks:\n  mailcow-network:\n    driver_opts:\n      com.docker.network.bridge.name: br-mailcow\n'
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == down ]]; then
  printf 'CORE-DOWN\n' >> "${MCP_UPDATE_TEST_LOG}"
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == pull ]]; then
  if [[ $# -eq 2 ]]; then
    printf 'IMAGE-PULL\n' >> "${MCP_UPDATE_TEST_LOG}"
    if [[ "${MCP_UPDATE_FAIL_MODE:-}" == mcp-inclusive ||
          "${MCP_UPDATE_FAIL_MODE:-}" == core ]]; then
      exit 1
    fi
  else
    printf 'CORE-PULL %s\n' "${*:3}" >> "${MCP_UPDATE_TEST_LOG}"
    [[ "${MCP_UPDATE_FAIL_MODE:-}" == core ]] && exit 1
  fi
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == up ]]; then
  offered="$(sed -n 's/^MCP_UPDATE_OFFERED=//p' mailcow.conf)"
  if [[ $# -eq 4 ]]; then
    printf 'CORE-UP offered=%s\n' "${offered:-missing}" >> "${MCP_UPDATE_TEST_LOG}"
  else
    printf 'CORE-ONLY-UP offered=%s services=%s\n' \
      "${offered:-missing}" "${*:5}" >> "${MCP_UPDATE_TEST_LOG}"
    [[ "${MCP_UPDATE_FAIL_MODE:-}" == core ]] && exit 1
  fi
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == ps ]]; then
  exit 0
fi
if [[ "${1:-}" == images ]]; then
  exit 0
fi
if [[ "${1:-}" == pull ]]; then
  exit 0
fi
exit 0
EOF

  cat > "${mock_bin}/git" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  rev-parse)
    if [[ " $* " == *" --abbrev-ref HEAD "* ]]; then
      printf 'master\n'
    else
      printf '0123456789abcdef0123456789abcdef01234567\n'
    fi
    ;;
  describe) printf '2026-07\n' ;;
  log)
    [[ " $* " == *" --format=%ci "* ]] && printf '2026-07-26 00:00:00 +0000\n'
    ;;
  config)
    [[ " $* " == *" --get remote.origin.url "* ]] &&
      printf 'https://github.com/mailcow/mailcow-dockerized\n'
    ;;
  diff-index|fetch|show|diff) exit 0 ;;
esac
exit 0
EOF

  cat > "${mock_bin}/curl" <<'EOF'
#!/usr/bin/env bash
printf '200'
EOF
  cat > "${mock_bin}/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat > "${mock_bin}/id" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == -u ]] && printf '0\n'
EOF
  cat > "${mock_bin}/sed" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -i ]]; then
  exit 0
fi
exec /usr/bin/sed "$@"
EOF
  cat > "${mock_bin}/cp" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -n ]]; then
  exit 0
fi
exec /bin/cp "$@"
EOF
  cat > "${mock_bin}/iptables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat > "${mock_bin}/ip" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod +x "${mock_bin}/"*

  cp -R "${case_dir}" "${candidate_failure_dir}"
  cp -R "${case_dir}" "${damaged_config_dir}"
  cp -R "${case_dir}" "${mcp_failure_dir}"
  cp -R "${case_dir}" "${core_failure_dir}"
  for variant_dir in "${mcp_failure_dir}" "${core_failure_dir}"; do
    write_config "${variant_dir}/mailcow.conf" foo,mcp,bar
    printf 'IPV4_NETWORK=172.22.1\nENABLE_IPV6=false\n' >> "${variant_dir}/mailcow.conf"
  done

  write_config "${damaged_config_dir}/mailcow.conf" foo,bar
  printf 'IPV4_NETWORK=172.22.1\nENABLE_IPV6=false\n' \
    >> "${damaged_config_dir}/mailcow.conf"
  sed -i '' '/^MCP_ENCRYPTION_KEY=/d' "${damaged_config_dir}/mailcow.conf"
  grep '^MCP_' "${damaged_config_dir}/mailcow.conf" \
    > "${damaged_config_dir}/mcp-config-before"

  update_status=0
  (
    cd "${candidate_failure_dir}"
    PATH="${candidate_failure_dir}/bin:${PATH}" \
      MCP_UPDATE_TEST_LOG="${candidate_failure_dir}/update.log" \
      MCP_UPDATE_FAIL_MODE=candidate-config \
      bash "${candidate_failure_dir}/update.sh" --dev --force --skip-ping-check \
      > "${candidate_failure_dir}/output.log" 2>&1
  ) || update_status=$?
  test "${update_status}" -ne 0 ||
    fail "updater accepted an invalid merged Compose candidate"
  test "$(grep -c '^CONFIG-Q ' "${candidate_failure_dir}/update.log" || true)" = 2 ||
    fail "updater did not reach the failing merged-candidate validation"
  if grep -Eq '^CORE-DOWN$|^IMAGE-PULL$' "${candidate_failure_dir}/update.log"; then
    fail "updater stopped core or pulled candidate images before validating the merged candidate"
  fi
  pass "invalid merged Compose candidate aborts before core teardown"

  update_status=0
  (
    cd "${damaged_config_dir}"
    PATH="${damaged_config_dir}/bin:${PATH}" \
      MCP_UPDATE_TEST_LOG="${damaged_config_dir}/update.log" \
      bash "${damaged_config_dir}/update.sh" --dev --force --skip-ping-check \
      > "${damaged_config_dir}/output.log" 2>&1
  ) || update_status=$?
  test "${update_status}" = 0 ||
    fail "disabled damaged MCP configuration blocked the core update"
  grep -qx 'CORE-DOWN' "${damaged_config_dir}/update.log" ||
    fail "core update did not continue through teardown with disabled damaged MCP configuration"
  grep -qx 'IMAGE-PULL' "${damaged_config_dir}/update.log" ||
    fail "core update did not continue through image pull with disabled damaged MCP configuration"
  grep -qx 'CORE-UP offered=0' "${damaged_config_dir}/update.log" ||
    fail "core update did not restart while the MCP offer remained suppressed"
  grep '^MCP_' "${damaged_config_dir}/mailcow.conf" \
    > "${damaged_config_dir}/mcp-config-after"
  assert_file_equals \
    "${damaged_config_dir}/mcp-config-before" \
    "${damaged_config_dir}/mcp-config-after" \
    "core update changed disabled damaged MCP configuration"
  if grep -q '^MCP-LIFECYCLE enable$' "${damaged_config_dir}/update.log"; then
    fail "disabled damaged MCP configuration was offered for activation"
  fi
  grep -q 'MCP configuration is unavailable' "${damaged_config_dir}/output.log" ||
    fail "core update did not report the unavailable MCP configuration"
  pass "disabled damaged MCP configuration does not block the core update"

  (
    cd "${case_dir}"
    COMPOSE_PROFILES=host-override \
      PATH="${mock_bin}:${PATH}" \
      MCP_UPDATE_TEST_LOG="${update_log}" \
      bash "${case_dir}/update.sh" --dev --force --skip-ping-check \
      > "${case_dir}/output.log" 2>&1
  ) || {
    sed -n '1,240p' "${case_dir}/output.log" >&2
    fail "stubbed updater run failed"
  }

  config_calls="$(grep -c '^CONFIG-Q ' "${update_log}" || true)"
  test "${config_calls}" = 2 ||
    fail "update did not validate Compose exactly before and after merge"
  test "$(grep -c '^CONFIG-Q marker=1 inherited=unset$' "${update_log}" || true)" = 2 ||
    fail "update validation ran before MCP preparation or inherited COMPOSE_PROFILES"
  awk '
    /^CONFIG-Q / { config_count++; if (config_count == 1) first = NR; else second = NR }
    /^CORE-DOWN$/ { down = NR }
    /^IMAGE-PULL$/ { pull = NR }
    END { exit !(first < second && second < down && down < pull) }
  ' "${update_log}" || fail "post-merge validation ran in the wrong updater sequence"
  grep -qx 'CORE-UP offered=0' "${update_log}" ||
    fail "one-time MCP offer was handled before core startup"
  grep -qx 'MCP_UPDATE_OFFERED=1' "${case_dir}/mailcow.conf" ||
    fail "one-time MCP offer was not recorded after core startup"
  if grep -q '^MCP-LIFECYCLE enable$' "${update_log}"; then
    fail "forced updater invoked MCP enable"
  fi
  if grep -q 'purge' "${update_log}"; then
    fail "ordinary update invoked MCP purge"
  fi
  pass "updater prepares MCP config, validates post-merge, and stays non-activating"

  update_status=0
  (
    cd "${mcp_failure_dir}"
    PATH="${mcp_failure_dir}/bin:${PATH}" \
      MCP_UPDATE_TEST_LOG="${mcp_failure_dir}/update.log" \
      MCP_UPDATE_FAIL_MODE=mcp-inclusive \
      bash "${mcp_failure_dir}/update.sh" --dev --force --skip-ping-check \
      > "${mcp_failure_dir}/output.log" 2>&1
  ) || update_status=$?
  test "${update_status}" = 0 ||
    fail "updater failed after successful core-only recovery"
  grep -q '^CORE-PULL mysql-mailcow nginx-mailcow postfix-mailcow$' \
    "${mcp_failure_dir}/update.log" ||
    fail "MCP-inclusive pull failure did not retry the derived core service set"
  grep -q '^CORE-ONLY-UP offered=0 services=mysql-mailcow nginx-mailcow postfix-mailcow$' \
    "${mcp_failure_dir}/update.log" ||
    fail "updater did not start the derived core service set independently"
  if grep -E '^CORE-(PULL|ONLY-UP).*mcp-(db-init|mailcow)' \
    "${mcp_failure_dir}/update.log"; then
    fail "core-only recovery included an MCP service"
  fi
  grep -qx 'MCP_UPDATE_OFFERED=1' "${mcp_failure_dir}/mailcow.conf" ||
    fail "offer was not handled after confirmed core-only startup"
  grep -q 'MCP services failed' "${mcp_failure_dir}/output.log" ||
    fail "successful core-only recovery did not report the MCP failure separately"

  update_status=0
  (
    cd "${core_failure_dir}"
    PATH="${core_failure_dir}/bin:${PATH}" \
      MCP_UPDATE_TEST_LOG="${core_failure_dir}/update.log" \
      MCP_UPDATE_FAIL_MODE=core \
      bash "${core_failure_dir}/update.sh" --dev --force --skip-ping-check \
      > "${core_failure_dir}/output.log" 2>&1
  ) || update_status=$?
  test "${update_status}" -ne 0 ||
    fail "updater reported success after core-only recovery failed"
  grep -qx 'MCP_UPDATE_OFFERED=0' "${core_failure_dir}/mailcow.conf" ||
    fail "updater handled the MCP offer without confirmed core startup"
  grep -q 'Core mailcow startup failed' "${core_failure_dir}/output.log" ||
    fail "updater did not distinguish the core startup failure"
  pass "updater recovers core independently and distinguishes core failure"
}

test_compose_forwards_mcp_oauth_policy_overrides() {
  local case_dir="${TEST_DIR}/compose-oauth-policy"
  local default_config="${case_dir}/mailcow.defaults.conf"
  local override_config="${case_dir}/mailcow.conf"
  local compose_json
  local redirects="https://operator.example.test/oauth/callback,https://backup.example.test/callback?mode=manual"
  local allow_loopback="0"
  local registrations_per_hour="37"
  local login_attempts="7"
  local login_window_seconds="1200"

  mkdir -p "${case_dir}"
  write_config "${default_config}" mcp
  sed \
    -e "s|^MCP_OAUTH_ALLOWED_REDIRECT_URIS=.*|MCP_OAUTH_ALLOWED_REDIRECT_URIS=${redirects}|" \
    -e "s|^MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS=.*|MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS=${allow_loopback}|" \
    -e "s|^MCP_REGISTRATIONS_PER_HOUR=.*|MCP_REGISTRATIONS_PER_HOUR=${registrations_per_hour}|" \
    -e "s|^MCP_LOGIN_ATTEMPTS=.*|MCP_LOGIN_ATTEMPTS=${login_attempts}|" \
    -e "s|^MCP_LOGIN_WINDOW_SECONDS=.*|MCP_LOGIN_WINDOW_SECONDS=${login_window_seconds}|" \
    "${default_config}" > "${override_config}"
  chmod 600 "${override_config}"

  compose_json="$(
    unset \
      MCP_OAUTH_ALLOWED_REDIRECT_URIS \
      MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS \
      MCP_REGISTRATIONS_PER_HOUR \
      MCP_LOGIN_ATTEMPTS \
      MCP_LOGIN_WINDOW_SECONDS
    docker compose \
      --env-file "${override_config}" \
      -f "${REPO_DIR}/docker-compose.yml" \
      --profile mcp \
      config --format json \
      2> "${case_dir}/compose.stderr"
  )" || fail "Compose could not render the MCP profile"

  if ! printf '%s' "${compose_json}" | python3 -c '
import json
import sys

config = json.load(sys.stdin)
environment = config["services"]["mcp-mailcow"]["environment"]
expected = {
    "MCP_OAUTH_ALLOWED_REDIRECT_URIS": sys.argv[1],
    "MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS": sys.argv[2],
    "MCP_REGISTRATIONS_PER_HOUR": sys.argv[3],
    "MCP_LOGIN_ATTEMPTS": sys.argv[4],
    "MCP_LOGIN_WINDOW_SECONDS": sys.argv[5],
}
actual = {key: environment.get(key) for key in expected}
if actual != expected:
    raise SystemExit(
        "mcp-mailcow did not preserve OAuth policy overrides: "
        f"expected={expected!r}, actual={actual!r}"
    )
volumes = config["services"]["mcp-mailcow"]["volumes"]
trust_mounts = [
    volume for volume in volumes
    if volume.get("target") == "/etc/ssl/mail/cert.pem"
]
if (
    len(trust_mounts) != 1
    or not trust_mounts[0].get("read_only")
    or not trust_mounts[0].get("source", "").endswith("/data/assets/ssl/cert.pem")
):
    raise SystemExit(
        "mcp-mailcow does not mount only the mailcow certificate read-only: "
        f"{trust_mounts!r}"
    )
' "${redirects}" "${allow_loopback}" "${registrations_per_hour}" \
    "${login_attempts}" "${login_window_seconds}"; then
    fail "Compose did not forward MCP OAuth policy overrides unchanged"
  fi

  pass "Compose forwards MCP OAuth policy overrides unchanged"
}

test_mcp_image_release_policy() {
  grep -qE 'ghcr\.io/[^/]+/mcp:0\.1\.0' "${REPO_DIR}/docker-compose.yml" ||
    fail "Compose does not pin the MCP image release"
  grep -q 'linux/amd64' "${REPO_DIR}/.github/workflows/mcp_release.yml" ||
    fail "MCP release workflow does not build the supported architecture"
  mcp_images="$(awk '
    /^    mcp-(db-init|mailcow):/ { in_mcp_service = 1; next }
    /^    [^[:space:]]/ { in_mcp_service = 0 }
    in_mcp_service && /^[[:space:]]+image:/ { print }
  ' "${REPO_DIR}/docker-compose.yml")"
  test "$(grep -cE 'image: ghcr\.io/[^/]+/mcp:0\.1\.0' <<< "${mcp_images}")" = 2 ||
    fail "both MCP services do not use the pinned MCP image release"
  # Both MCP services must resolve to the same registry namespace. Comparing the
  # deduplicated set against the first line avoids wc -l, whose output is padded
  # on BSD/macOS and would not compare equal to a bare count.
  test "$(sort -u <<< "${mcp_images}")" = "$(head -n 1 <<< "${mcp_images}")" ||
    fail "MCP services disagree on the pinned image reference"
  ! grep -q 'image:.*latest' <<< "${mcp_images}" ||
    fail "an MCP service uses an unpinned latest image reference"
  pass "MCP image release policy pins Compose and publishes the release image"
}

[[ -x "${MCP_SCRIPT}" ]] || fail "helper-scripts/mcp.sh is absent"

if [[ "${MCP_TEST_FOCUS:-}" == update ]]; then
  test_update_runtime_preflight_and_post_merge_validation
  exit 0
fi
if [[ "${MCP_TEST_FOCUS:-}" == purge ]]; then
  test_purge_removes_validated_stopped_app_before_data
  exit 0
fi
if [[ "${MCP_TEST_FOCUS:-}" == compose ]]; then
  test_compose_forwards_mcp_oauth_policy_overrides
  exit 0
fi
if [[ "${MCP_TEST_FOCUS:-}" == local-probe ]]; then
  test_https_verification_supports_local_backend_mode
  test_invalid_local_probe_config_aborts_before_activation
  exit 0
fi

test_compose_forwards_mcp_oauth_policy_overrides
test_mcp_image_release_policy
test_enable_success_and_idempotence
test_already_enabled_enable_migrates_defaults_without_side_effects
test_enable_rolls_back_each_failure
test_rollback_preserves_preexisting_mcp_container
test_baseline_inventory_failure_aborts_without_mutation
test_term_during_activation_runs_transaction_rollback
test_term_during_config_preparation_restores_exact_backup
test_term_during_rollback_cleanup_finishes_rollback
test_term_during_rollback_setup_cannot_bypass_rollback
test_rollback_reports_inventory_and_removal_failures
test_https_verification_retries_and_validates_metadata
test_https_verification_supports_local_backend_mode
test_invalid_local_probe_config_aborts_before_activation
test_disable_is_idempotent_and_preserves_data_configuration
test_status_retry_and_purge_guards
test_inherited_profile_is_not_forwarded_to_compose
test_purge_requires_disabled_state
test_purge_removes_validated_stopped_app_before_data
test_update_offer_never_activates_unattended_or_skip_start
test_update_runtime_preflight_and_post_merge_validation
