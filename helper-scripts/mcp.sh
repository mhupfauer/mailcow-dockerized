#!/usr/bin/env bash

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MAILCOW_CONF="${INSTALL_DIR}/mailcow.conf"
MCP_CONFIG_HELPER="${INSTALL_DIR}/_modules/scripts/mcp_config.sh"
MCP_LOCK_DIR="${INSTALL_DIR}/.mcp-lifecycle.lock"
MCP_BACKUP="${MAILCOW_CONF}.mcp.bak"
MCP_LOCKED=n
MCP_FINISHING=n
MCP_TRANSACTION_ACTIVE=n
MCP_TRANSACTION_ROLLING_BACK=n
MCP_ROLLBACK_SIGNAL_STATUS=0
MCP_TRANSACTION_PRIOR_APP_IDS=
MCP_TRANSACTION_PRIOR_INIT_IDS=
MCP_LIFECYCLE_PID=$$
export MCP_LIFECYCLE_PID

if [[ ! -r "${MCP_CONFIG_HELPER}" ]]; then
  echo "MCP configuration helper is missing: ${MCP_CONFIG_HELPER}" >&2
  exit 1
fi
# shellcheck source=../_modules/scripts/mcp_config.sh
source "${MCP_CONFIG_HELPER}"

mcp_cleanup_lock() {
  if [[ "${MCP_LOCKED}" == y ]]; then
    rmdir -- "${MCP_LOCK_DIR}" 2>/dev/null || true
  fi
}

mcp_finish() {
  local status="$1"
  local rollback_status=0

  MCP_FINISHING=y
  MCP_ROLLBACK_SIGNAL_STATUS=0
  trap 'mcp_defer_rollback_signal 130' INT
  trap 'mcp_defer_rollback_signal 143' TERM
  trap - EXIT
  if [[ "${MCP_TRANSACTION_ACTIVE}" == y ]]; then
    mcp_rollback_transaction || rollback_status=$?
    if [[ "${rollback_status}" -ge 128 ]]; then
      status="${rollback_status}"
    elif [[ "${rollback_status}" -ne 0 ]]; then
      echo "MCP transaction rollback cleanup failed" >&2
      if [[ "${status}" -eq 0 ]]; then
        status=1
      fi
    fi
  fi
  trap '' INT TERM
  if [[ "${MCP_ROLLBACK_SIGNAL_STATUS}" -ge 128 ]]; then
    status="${MCP_ROLLBACK_SIGNAL_STATUS}"
  fi
  mcp_cleanup_lock
  exit "${status}"
}

trap 'mcp_finish "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mcp_require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "You need to be root" >&2
    return 1
  fi
}

mcp_acquire_lock() {
  if ! mkdir -- "${MCP_LOCK_DIR}" 2>/dev/null; then
    echo "Another MCP lifecycle operation is already running" >&2
    return 1
  fi
  MCP_LOCKED=y
}

mcp_compose() {
  (
    unset COMPOSE_PROFILES
    cd "${INSTALL_DIR}" || exit 1
    docker compose "$@"
  )
}

mcp_config_profiles() {
  mcp_config_value "${MAILCOW_CONF}" COMPOSE_PROFILES
}

mcp_is_enabled() {
  local profiles
  profiles="$(mcp_config_profiles)" || return 1
  mcp_profile_contains "${profiles}" mcp
}

mcp_atomic_set_state() {
  local state="$1"
  local mark_offered="${2:-n}"
  local profiles
  local desired_profiles
  local temp_config

  profiles="$(mcp_config_profiles)" || return 1
  if [[ "${state}" == enabled ]]; then
    desired_profiles="$(mcp_profile_add "${profiles}" mcp)"
  else
    desired_profiles="$(mcp_profile_remove "${profiles}" mcp)"
  fi

  umask 077
  temp_config="$(mktemp "${INSTALL_DIR}/.mailcow.conf.mcp-state.XXXXXX")" || return 1
  if ! awk -v profiles="${desired_profiles}" -v mark_offered="${mark_offered}" '
    BEGIN { profile_count = 0; offer_count = 0 }
    /^COMPOSE_PROFILES=/ {
      print "COMPOSE_PROFILES=" profiles
      profile_count++
      next
    }
    /^MCP_UPDATE_OFFERED=/ {
      if (mark_offered == "y") {
        print "MCP_UPDATE_OFFERED=1"
      } else {
        print
      }
      offer_count++
      next
    }
    { print }
    END {
      if (profile_count != 1 || offer_count != 1) {
        exit 1
      }
    }
  ' "${MAILCOW_CONF}" > "${temp_config}"; then
    rm -f -- "${temp_config}"
    return 1
  fi
  chmod 600 "${temp_config}" || {
    rm -f -- "${temp_config}"
    return 1
  }
  mcp_validate_config "${temp_config}" "${state}" || {
    rm -f -- "${temp_config}"
    return 1
  }
  mv -- "${temp_config}" "${MAILCOW_CONF}"
}

mcp_create_backup() {
  umask 077
  cp -- "${MAILCOW_CONF}" "${MCP_BACKUP}" || return 1
  chmod 600 "${MCP_BACKUP}"
}

mcp_restore_backup() {
  local temp_config

  umask 077
  temp_config="$(mktemp "${INSTALL_DIR}/.mailcow.conf.mcp-restore.XXXXXX")" || return 1
  cp -- "${MCP_BACKUP}" "${temp_config}" || {
    rm -f -- "${temp_config}"
    return 1
  }
  chmod 600 "${temp_config}" || {
    rm -f -- "${temp_config}"
    return 1
  }
  mv -- "${temp_config}" "${MAILCOW_CONF}"
}

mcp_container_ids() {
  mcp_compose --profile mcp ps -aq "$1"
}

mcp_validate_container_ids() {
  local ids="$1"
  local container_id

  while IFS= read -r container_id; do
    [[ -n "${container_id}" ]] || continue
    if [[ ! "${container_id}" =~ ^[[:xdigit:]]{12,64}$ ]]; then
      echo "Docker returned an invalid MCP container ID" >&2
      return 1
    fi
  done <<< "${ids}"
}

mcp_remove_new_containers() {
  local old_app_ids="$1"
  local old_init_ids="$2"
  local current_ids
  local container_id
  local cleanup_failed=n

  if ! current_ids="$(mcp_container_ids mcp-mailcow 2>/dev/null)" ||
    ! mcp_validate_container_ids "${current_ids}"; then
    echo "Could not inventory MCP application containers during rollback" >&2
    cleanup_failed=y
  else
    while IFS= read -r container_id; do
      [[ -n "${container_id}" ]] || continue
      if ! grep -Fqx "${container_id}" <<< "${old_app_ids}"; then
        if ! docker rm -f "${container_id}" >/dev/null 2>&1; then
          echo "Could not remove new MCP application container ${container_id}" >&2
          cleanup_failed=y
        fi
      fi
    done <<< "${current_ids}"
  fi

  if ! current_ids="$(mcp_container_ids mcp-db-init 2>/dev/null)" ||
    ! mcp_validate_container_ids "${current_ids}"; then
    echo "Could not inventory MCP initializer containers during rollback" >&2
    cleanup_failed=y
  else
    while IFS= read -r container_id; do
      [[ -n "${container_id}" ]] || continue
      if ! grep -Fqx "${container_id}" <<< "${old_init_ids}"; then
        if ! docker rm -f "${container_id}" >/dev/null 2>&1; then
          echo "Could not remove new MCP initializer container ${container_id}" >&2
          cleanup_failed=y
        fi
      fi
    done <<< "${current_ids}"
  fi

  [[ "${cleanup_failed}" == n ]]
}

mcp_recreate_nginx() {
  mcp_compose up -d --no-deps --force-recreate nginx-mailcow
}

mcp_defer_rollback_signal() {
  local status="$1"

  if [[ "${MCP_ROLLBACK_SIGNAL_STATUS}" -eq 0 ||
        "${status}" -eq 143 ]]; then
    MCP_ROLLBACK_SIGNAL_STATUS="${status}"
  fi
}

mcp_rollback_transaction() {
  local rollback_failed=n
  local signal_status

  if [[ "${MCP_TRANSACTION_ROLLING_BACK}" == y ]]; then
    return 1
  fi
  MCP_TRANSACTION_ROLLING_BACK=y
  if [[ "${MCP_FINISHING}" != y ]]; then
    MCP_ROLLBACK_SIGNAL_STATUS=0
    trap 'mcp_defer_rollback_signal 130' INT
    trap 'mcp_defer_rollback_signal 143' TERM
  fi

  if ! mcp_remove_new_containers \
    "${MCP_TRANSACTION_PRIOR_APP_IDS}" "${MCP_TRANSACTION_PRIOR_INIT_IDS}"; then
    rollback_failed=y
  fi
  if ! mcp_restore_backup; then
    echo "Could not restore the pre-activation MCP configuration" >&2
    rollback_failed=y
  fi
  if ! mcp_recreate_nginx; then
    echo "Could not recreate nginx after MCP rollback" >&2
    rollback_failed=y
  fi

  if [[ "${rollback_failed}" == y ]]; then
    echo "MCP rollback cleanup failed; configuration/nginx restoration was still attempted" >&2
  fi

  MCP_TRANSACTION_ROLLING_BACK=n
  MCP_TRANSACTION_ACTIVE=n
  if [[ "${MCP_FINISHING}" != y ]]; then
    trap 'exit 130' INT
    trap 'exit 143' TERM
  fi
  signal_status="${MCP_ROLLBACK_SIGNAL_STATUS}"
  if [[ "${signal_status}" -ne 0 ]]; then
    return "${signal_status}"
  fi
  [[ "${rollback_failed}" == n ]]
}

mcp_verify_https() {
  local hostname
  local issuer
  local resource
  local authorization_body
  local protected_body
  local response_headers
  local status
  local challenge
  local attempt
  local ready=n

  hostname="$(mcp_config_value "${MAILCOW_CONF}" MAILCOW_HOSTNAME)" || {
    echo "MAILCOW_HOSTNAME must be set exactly once" >&2
    return 1
  }
  command -v jq >/dev/null 2>&1 || {
    echo "jq is required to validate MCP discovery metadata" >&2
    return 1
  }

  issuer="https://${hostname}"
  resource="${issuer}/mcp"
  umask 077
  authorization_body="$(mktemp "${INSTALL_DIR}/.mcp-authorization.XXXXXX")" || return 1
  protected_body="$(mktemp "${INSTALL_DIR}/.mcp-protected.XXXXXX")" || {
    rm -f -- "${authorization_body}"
    return 1
  }
  response_headers="$(mktemp "${INSTALL_DIR}/.mcp-headers.XXXXXX")" || {
    rm -f -- "${authorization_body}" "${protected_body}"
    return 1
  }

  for attempt in 1 2 3 4 5 6; do
    : > "${authorization_body}"
    : > "${protected_body}"
    : > "${response_headers}"
    challenge=

    status="$(curl --connect-timeout 5 --max-time 15 --silent --show-error \
      --output "${authorization_body}" --write-out '%{http_code}' \
      "${issuer}/.well-known/oauth-authorization-server")" || status=000
    if [[ "${status}" == 200 ]] &&
      jq -e --arg issuer "${issuer}" \
        'type == "object" and .issuer == $issuer' \
        "${authorization_body}" >/dev/null; then
      status="$(curl --connect-timeout 5 --max-time 15 --silent --show-error \
        --output "${protected_body}" --write-out '%{http_code}' \
        "${issuer}/.well-known/oauth-protected-resource/mcp")" || status=000
      if [[ "${status}" == 200 ]] &&
        jq -e --arg resource "${resource}" --arg issuer "${issuer}" \
          'type == "object" and .resource == $resource and
           (.authorization_servers | type == "array" and index($issuer) != null)' \
          "${protected_body}" >/dev/null; then
        status="$(curl --connect-timeout 5 --max-time 15 --silent --show-error \
          --dump-header "${response_headers}" --output /dev/null \
          --write-out '%{http_code}' -X POST "${resource}")" || status=000
        if [[ "${status}" == 401 ]]; then
          challenge="$(tr -d '\r' < "${response_headers}" |
            awk -F': ' \
              'tolower($1) == "www-authenticate" {
                print substr($0, index($0, ":") + 2)
              }' |
            tail -1)"
          if [[ "${challenge}" == \
            "Bearer resource_metadata=\"${issuer}/.well-known/oauth-protected-resource/mcp\"" ]]; then
            ready=y
            break
          fi
        fi
      fi
    fi

    if [[ "${attempt}" -lt 6 ]]; then
      sleep 5
    fi
  done
  if [[ "${ready}" != y ]]; then
    echo "MCP HTTPS discovery and authentication contract did not become ready" >&2
    rm -f -- "${authorization_body}" "${protected_body}" "${response_headers}"
    return 1
  fi

  rm -f -- "${authorization_body}" "${protected_body}" "${response_headers}"
}

mcp_activate() {
  mcp_compose --profile mcp config -q &&
    mcp_compose --profile mcp pull mcp-mailcow &&
    mcp_compose up -d mysql-mailcow &&
    mcp_compose --profile mcp run --rm mcp-db-init node dist/db/init.js &&
    mcp_compose --profile mcp run --rm --no-deps mcp-mailcow node dist/db/migrations.js &&
    mcp_compose --profile mcp up -d --no-deps mcp-mailcow &&
    mcp_recreate_nginx &&
    mcp_verify_https
}

mcp_enable() {
  local retry="${1:-n}"
  local prior_app_ids
  local prior_init_ids
  local rollback_status=0

  mcp_require_root || return 1
  mcp_acquire_lock || return 1
  mcp_create_backup || return 1

  if mcp_is_enabled && [[ "${retry}" != y ]]; then
    if ! mcp_validate_config "${MAILCOW_CONF}" enabled; then
      return 1
    fi
    echo "MCP is already enabled"
    return 0
  fi

  if ! prior_app_ids="$(mcp_container_ids mcp-mailcow 2>/dev/null)" ||
    ! mcp_validate_container_ids "${prior_app_ids}"; then
    echo "Could not capture the baseline MCP application container inventory" >&2
    return 1
  fi
  if ! prior_init_ids="$(mcp_container_ids mcp-db-init 2>/dev/null)" ||
    ! mcp_validate_container_ids "${prior_init_ids}"; then
    echo "Could not capture the baseline MCP initializer container inventory" >&2
    return 1
  fi

  MCP_TRANSACTION_PRIOR_APP_IDS="${prior_app_ids}"
  MCP_TRANSACTION_PRIOR_INIT_IDS="${prior_init_ids}"
  MCP_TRANSACTION_ACTIVE=y

  if ! mcp_prepare_config "${MAILCOW_CONF}" upgrade; then
    mcp_rollback_transaction || rollback_status=$?
    echo "MCP configuration preparation failed; no activation was attempted" >&2
    if [[ "${rollback_status}" -ge 128 ]]; then
      return "${rollback_status}"
    fi
    [[ "${rollback_status}" -eq 0 ]] ||
      echo "MCP transaction rollback cleanup failed" >&2
    return 1
  fi

  if mcp_is_enabled; then
    if ! mcp_validate_config "${MAILCOW_CONF}" enabled; then
      mcp_rollback_transaction || rollback_status=$?
      if [[ "${rollback_status}" -ge 128 ]]; then
        return "${rollback_status}"
      fi
      [[ "${rollback_status}" -eq 0 ]] ||
        echo "MCP transaction rollback cleanup failed" >&2
      return 1
    fi
  elif ! mcp_validate_config "${MAILCOW_CONF}" disabled; then
    mcp_rollback_transaction || rollback_status=$?
    if [[ "${rollback_status}" -ge 128 ]]; then
      return "${rollback_status}"
    fi
    [[ "${rollback_status}" -eq 0 ]] ||
      echo "MCP transaction rollback cleanup failed" >&2
    return 1
  fi

  if ! mcp_atomic_set_state enabled y; then
    mcp_rollback_transaction || rollback_status=$?
    echo "MCP activation failed while updating configuration; previous state restored" >&2
    if [[ "${rollback_status}" -ge 128 ]]; then
      return "${rollback_status}"
    fi
    [[ "${rollback_status}" -eq 0 ]] ||
      echo "MCP transaction rollback cleanup failed" >&2
    return 1
  fi

  if ! mcp_activate; then
    mcp_rollback_transaction || rollback_status=$?
    echo "MCP activation failed; previous configuration restored" >&2
    if [[ "${rollback_status}" -ge 128 ]]; then
      return "${rollback_status}"
    fi
    [[ "${rollback_status}" -eq 0 ]] ||
      echo "MCP transaction rollback cleanup failed" >&2
    return 1
  fi

  MCP_TRANSACTION_ACTIVE=n
  echo "MCP enabled"
}

mcp_disable() {
  mcp_require_root || return 1
  mcp_acquire_lock || return 1

  if ! mcp_is_enabled; then
    mcp_validate_config "${MAILCOW_CONF}" disabled || return 1
    echo "MCP is already disabled"
    return 0
  fi
  mcp_validate_config "${MAILCOW_CONF}" enabled || return 1
  mcp_create_backup || return 1
  mcp_atomic_set_state disabled || return 1

  mcp_compose --profile mcp stop mcp-mailcow >/dev/null 2>&1 || true
  if ! mcp_recreate_nginx; then
    echo "MCP is disabled in configuration, but nginx recreation failed" >&2
    return 1
  fi
  echo "MCP disabled; database, credentials, OAuth state, and attachments were preserved"
}

mcp_status() {
  if mcp_is_enabled; then
    if mcp_validate_config "${MAILCOW_CONF}" enabled; then
      echo "MCP status: enabled"
      return 0
    fi
  else
    if mcp_validate_config "${MAILCOW_CONF}" disabled; then
      echo "MCP status: disabled"
      return 0
    fi
  fi
  echo "MCP status: invalid configuration" >&2
  return 1
}

mcp_resolve_attachment_volume() {
  local project_name="$1"
  local volume_output
  local volume_name
  local labels
  local count

  if ! volume_output="$(docker volume ls --quiet \
    --filter "label=com.docker.compose.project=${project_name}" \
    --filter "label=com.docker.compose.volume=mcp-attachments-vol-1")"; then
    echo "Could not query Docker for the MCP attachment volume" >&2
    return 1
  fi
  count="$(printf '%s\n' "${volume_output}" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "${count}" == 0 ]]; then
    printf '\n'
    return 0
  fi
  if [[ "${count}" != 1 ]]; then
    echo "Docker returned multiple MCP attachment volumes" >&2
    return 1
  fi
  volume_name="$(printf '%s\n' "${volume_output}" | sed '/^$/d')"
  if [[ ! "${volume_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    echo "Docker returned an invalid MCP attachment volume name" >&2
    return 1
  fi
  if ! labels="$(docker volume inspect "${volume_name}" --format \
    '{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.volume" }}')"; then
    echo "Could not inspect the MCP attachment volume" >&2
    return 1
  fi
  if [[ "${labels}" != "${project_name}|mcp-attachments-vol-1" ]]; then
    echo "MCP attachment volume labels do not match the configured project" >&2
    return 1
  fi
  printf '%s\n' "${volume_name}"
}

mcp_purge() {
  local dbname
  local dbuser
  local dbroot
  local project_name
  local confirmation
  local sql
  local volume_name

  mcp_require_root || return 1
  mcp_acquire_lock || return 1
  if mcp_is_enabled; then
    echo "Disable MCP before purging its persistent data" >&2
    return 1
  fi
  mcp_validate_config "${MAILCOW_CONF}" disabled || return 1

  printf 'Type "PURGE mailcow_mcp" to permanently remove MCP data: '
  IFS= read -r confirmation || return 1
  if [[ "${confirmation}" != "PURGE mailcow_mcp" ]]; then
    echo "Purge confirmation did not match; nothing was removed" >&2
    return 1
  fi

  dbname="$(mcp_config_value "${MAILCOW_CONF}" MCP_DBNAME)" || return 1
  dbuser="$(mcp_config_value "${MAILCOW_CONF}" MCP_DBUSER)" || return 1
  dbroot="$(mcp_config_value "${MAILCOW_CONF}" DBROOT)" || return 1
  project_name="$(mcp_config_value "${MAILCOW_CONF}" COMPOSE_PROJECT_NAME)" || return 1
  [[ "${dbname}" =~ ^[A-Za-z_][A-Za-z0-9_]{0,63}$ ]] || return 1
  [[ "${dbuser}" =~ ^[A-Za-z_][A-Za-z0-9_]{0,63}$ ]] || return 1
  [[ "${project_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || return 1

  if ! volume_name="$(mcp_resolve_attachment_volume "${project_name}")"; then
    return 1
  fi
  sql="DROP DATABASE IF EXISTS \`${dbname}\`; DROP USER IF EXISTS '${dbuser}'@'%';"
  if ! printf '%s\n' "${sql}" |
    mcp_compose exec -T mysql-mailcow mysql -uroot "-p${dbroot}"; then
    echo "MCP database purge failed" >&2
    return 1
  fi
  if [[ -n "${volume_name}" ]] &&
    ! docker volume rm "${volume_name}" >/dev/null 2>&1; then
    echo "MCP database was purged, but attachment-volume removal failed" >&2
    return 1
  fi
  echo "MCP database and attachment volume purged"
}

mcp_usage() {
  echo "Usage: $0 enable|disable|status|retry|purge" >&2
}

case "${1:-}" in
  enable)
    [[ $# -eq 1 ]] || {
      mcp_usage
      exit 2
    }
    mcp_enable
    ;;
  disable)
    [[ $# -eq 1 ]] || {
      mcp_usage
      exit 2
    }
    mcp_disable
    ;;
  status)
    [[ $# -eq 1 ]] || {
      mcp_usage
      exit 2
    }
    mcp_status
    ;;
  retry)
    [[ $# -eq 1 ]] || {
      mcp_usage
      exit 2
    }
    mcp_enable y
    ;;
  purge)
    [[ $# -eq 1 ]] || {
      mcp_usage
      exit 2
    }
    mcp_purge
    ;;
  *)
    mcp_usage
    exit 2
    ;;
esac
