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

trap mcp_cleanup_lock EXIT
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

mcp_remove_new_containers() {
  local old_app_ids="$1"
  local old_init_ids="$2"
  local current_ids
  local container_id

  current_ids="$(mcp_container_ids mcp-mailcow 2>/dev/null || true)"
  while IFS= read -r container_id; do
    [[ -n "${container_id}" ]] || continue
    if ! grep -Fqx "${container_id}" <<< "${old_app_ids}"; then
      docker rm -f "${container_id}" >/dev/null 2>&1 || true
    fi
  done <<< "${current_ids}"

  current_ids="$(mcp_container_ids mcp-db-init 2>/dev/null || true)"
  while IFS= read -r container_id; do
    [[ -n "${container_id}" ]] || continue
    if ! grep -Fqx "${container_id}" <<< "${old_init_ids}"; then
      docker rm -f "${container_id}" >/dev/null 2>&1 || true
    fi
  done <<< "${current_ids}"
}

mcp_recreate_nginx() {
  mcp_compose up -d --no-deps --force-recreate nginx-mailcow
}

mcp_verify_https() {
  local hostname
  local status

  hostname="$(mcp_config_value "${MAILCOW_CONF}" MAILCOW_HOSTNAME)" || {
    echo "MAILCOW_HOSTNAME must be set exactly once" >&2
    return 1
  }
  curl --fail --silent --show-error \
    "https://${hostname}/.well-known/oauth-authorization-server" >/dev/null || return 1
  curl --fail --silent --show-error \
    "https://${hostname}/.well-known/oauth-protected-resource/mcp" >/dev/null || return 1
  status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    -X POST "https://${hostname}/mcp")" || return 1
  if [[ "${status}" != 401 ]]; then
    echo "MCP endpoint returned HTTP ${status}; expected 401" >&2
    return 1
  fi
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

  mcp_require_root || return 1
  mcp_acquire_lock || return 1
  mcp_create_backup || return 1

  if ! mcp_prepare_config "${MAILCOW_CONF}" upgrade; then
    mcp_restore_backup >/dev/null 2>&1 || true
    echo "MCP configuration preparation failed; no activation was attempted" >&2
    return 1
  fi

  if mcp_is_enabled; then
    mcp_validate_config "${MAILCOW_CONF}" enabled || return 1
    if [[ "${retry}" != y ]]; then
      echo "MCP is already enabled"
      return 0
    fi
  else
    mcp_validate_config "${MAILCOW_CONF}" disabled || return 1
  fi

  prior_app_ids="$(mcp_container_ids mcp-mailcow 2>/dev/null || true)"
  prior_init_ids="$(mcp_container_ids mcp-db-init 2>/dev/null || true)"

  if ! mcp_atomic_set_state enabled y; then
    mcp_restore_backup >/dev/null 2>&1 || true
    mcp_recreate_nginx >/dev/null 2>&1 || true
    echo "MCP activation failed while updating configuration; previous state restored" >&2
    return 1
  fi

  if ! mcp_activate; then
    mcp_remove_new_containers "${prior_app_ids}" "${prior_init_ids}"
    if ! mcp_restore_backup; then
      echo "MCP activation failed and the previous configuration could not be restored" >&2
      return 1
    fi
    if ! mcp_recreate_nginx; then
      echo "MCP activation failed; configuration was restored, but nginx recreation failed" >&2
      return 1
    fi
    echo "MCP activation failed; previous configuration restored" >&2
    return 1
  fi

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

  sql="DROP DATABASE IF EXISTS \`${dbname}\`; DROP USER IF EXISTS '${dbuser}'@'%';"
  if ! printf '%s\n' "${sql}" |
    mcp_compose exec -T mysql-mailcow mysql -uroot "-p${dbroot}"; then
    echo "MCP database purge failed" >&2
    return 1
  fi
  volume_name="${project_name}_mcp-attachments-vol-1"
  if docker volume inspect "${volume_name}" >/dev/null 2>&1 &&
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
