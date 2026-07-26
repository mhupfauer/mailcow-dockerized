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
EOF
  chmod 600 "${path}"
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
  *" rm -f new-app "*|*" rm -f new-init "*) stage=remove ;;
  *" compose exec -T mysql-mailcow "*) stage=purge-db ;;
  *" volume rm mailcowdockerized_mcp-attachments-vol-1 "*) stage=purge-volume ;;
esac

if [[ -n "${stage}" ]]; then
  printf '%s\n' "${stage}" >> "${MCP_TEST_STAGE_LOG}"
fi

if [[ "${1:-}" == "compose" && "${2:-}" == "--profile" && "${3:-}" == "mcp" &&
      "${4:-}" == "ps" && "${5:-}" == "-aq" ]]; then
  case "${6:-}" in
    mcp-mailcow)
      if [[ ",${MCP_TEST_EXISTING:-}," == *",mcp-mailcow,"* ]]; then
        printf 'existing-app\n'
      elif grep -qx 'app' "${MCP_TEST_STAGE_LOG}" 2>/dev/null; then
        printf 'new-app\n'
      fi
      ;;
    mcp-db-init)
      if [[ ",${MCP_TEST_EXISTING:-}," == *",mcp-db-init,"* ]]; then
        printf 'existing-init\n'
      elif grep -qx 'init' "${MCP_TEST_STAGE_LOG}" 2>/dev/null; then
        printf 'new-init\n'
      fi
      ;;
  esac
fi

if [[ -n "${stage}" && "${MCP_TEST_FAIL_STAGE:-}" == "${stage}" &&
      ! -e "${MCP_TEST_FAIL_MARKER}" ]]; then
  : > "${MCP_TEST_FAIL_MARKER}"
  exit 1
fi
EOF

  cat > "${case_dir}/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -u

printf 'curl %s\n' "$*" >> "${MCP_TEST_CALL_LOG}"
stage=discovery
[[ " $* " == *" -X POST "* && " $* " == *"/mcp "* ]] && stage=mcp-auth
printf '%s\n' "${stage}" >> "${MCP_TEST_STAGE_LOG}"

if [[ "${MCP_TEST_FAIL_STAGE:-}" == "${stage}" && ! -e "${MCP_TEST_FAIL_MARKER}" ]]; then
  : > "${MCP_TEST_FAIL_MARKER}"
  exit 1
fi

if [[ "${stage}" == "mcp-auth" ]]; then
  printf '401'
else
  printf '{}'
fi
EOF

  chmod +x "${case_dir}/helper-scripts/mcp.sh" "${case_dir}/bin/id" \
    "${case_dir}/bin/docker" "${case_dir}/bin/curl"
  printf '%s\n' "${case_dir}"
}

run_mcp() {
  local case_dir="$1"
  shift
  (
    cd "${case_dir}"
    PATH="${case_dir}/bin:${PATH}" \
      MCP_TEST_CONFIG="${case_dir}/mailcow.conf" \
      MCP_TEST_CALL_LOG="${case_dir}/calls.log" \
      MCP_TEST_STAGE_LOG="${case_dir}/stages.log" \
      MCP_TEST_FAIL_MARKER="${case_dir}/failed-once" \
      MCP_TEST_FAIL_STAGE="${MCP_TEST_FAIL_STAGE:-}" \
      MCP_TEST_EXISTING="${MCP_TEST_EXISTING:-}" \
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
    removed_calls="$(grep -c '|docker rm -f new-' "${case_dir}/calls.log" || true)"
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

  grep -q '|docker rm -f new-app' "${case_dir}/calls.log" ||
    fail "rollback did not remove the newly created application container"
  if grep -q '|docker rm -f existing-init' "${case_dir}/calls.log"; then
    fail "rollback removed a pre-existing MCP initializer container"
  fi
  assert_file_equals "${case_dir}/before.conf" "${case_dir}/mailcow.conf" \
    "rollback changed config while preserving a pre-existing container"
  pass "rollback removes only newly created MCP containers"
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
  assert_no_core_down "${case_dir}/calls.log"

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
  printf 'IMAGE-PULL\n' >> "${MCP_UPDATE_TEST_LOG}"
  exit 0
fi
if [[ "${1:-}" == compose && "${2:-}" == up ]]; then
  offered="$(sed -n 's/^MCP_UPDATE_OFFERED=//p' mailcow.conf)"
  printf 'CORE-UP offered=%s\n' "${offered:-missing}" >> "${MCP_UPDATE_TEST_LOG}"
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
    END { exit !(first < down && down < second && second < pull) }
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
}

[[ -x "${MCP_SCRIPT}" ]] || fail "helper-scripts/mcp.sh is absent"

test_enable_success_and_idempotence
test_enable_rolls_back_each_failure
test_rollback_preserves_preexisting_mcp_container
test_disable_is_idempotent_and_preserves_data_configuration
test_status_retry_and_purge_guards
test_inherited_profile_is_not_forwarded_to_compose
test_purge_requires_disabled_state
test_update_offer_never_activates_unattended_or_skip_start
test_update_runtime_preflight_and_post_merge_validation
