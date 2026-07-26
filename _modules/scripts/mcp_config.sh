#!/usr/bin/env bash
# _modules/scripts/mcp_config.sh
# THIS SCRIPT IS DESIGNED TO BE RUNNING BY MAILCOW SCRIPTS ONLY!

mcp_profile_contains() {
  local profiles="$1"
  local token="$2"
  local profile
  local -a profile_list=()

  [[ -n "${profiles}" ]] || return 1
  IFS=',' read -r -a profile_list <<< "${profiles}"
  for profile in "${profile_list[@]}"; do
    [[ "${profile}" == "${token}" ]] && return 0
  done
  return 1
}

mcp_profile_add() {
  local profiles="$1"
  local token="$2"

  if mcp_profile_contains "${profiles}" "${token}"; then
    printf '%s\n' "${profiles}"
  elif [[ -n "${profiles}" ]]; then
    printf '%s,%s\n' "${profiles}" "${token}"
  else
    printf '%s\n' "${token}"
  fi
}

mcp_profile_remove() {
  local profiles="$1"
  local token="$2"
  local profile
  local result=""
  local -a profile_list=()

  [[ -n "${profiles}" ]] || {
    printf '\n'
    return
  }
  IFS=',' read -r -a profile_list <<< "${profiles}"
  for profile in "${profile_list[@]}"; do
    [[ "${profile}" == "${token}" ]] && continue
    if [[ -n "${result}" ]]; then
      result="${result},"
    fi
    result+="${profile}"
  done
  printf '%s\n' "${result}"
}

mcp_config_value() {
  local config_path="$1"
  local key="$2"
  local line

  line="$(grep -E "^${key}=" "${config_path}" 2>/dev/null || true)"
  [[ "$(printf '%s\n' "${line}" | sed '/^$/d' | wc -l | tr -d ' ')" == "1" ]] || return 1
  printf '%s\n' "${line#*=}"
}

mcp_config_has_key() {
  grep -q "^$2=" "$1"
}

mcp_validate_config() {
  local config_path="$1"
  local state="$2"
  local dbpass
  local encryption_key
  local config_version
  local profiles

  [[ -f "${config_path}" ]] || {
    echo "MCP configuration file is missing" >&2
    return 1
  }
  [[ "${state}" == "enabled" || "${state}" == "disabled" ]] || {
    echo "MCP configuration state must be enabled or disabled" >&2
    return 1
  }

  config_version="$(mcp_config_value "${config_path}" MCP_CONFIG_VERSION)" || {
    echo "MCP_CONFIG_VERSION must be set exactly once" >&2
    return 1
  }
  [[ "${config_version}" == "1" ]] || {
    echo "Unsupported MCP_CONFIG_VERSION" >&2
    return 1
  }

  dbpass="$(mcp_config_value "${config_path}" MCP_DBPASS)" || {
    echo "MCP_DBPASS must be set exactly once" >&2
    return 1
  }
  [[ "${dbpass}" =~ ^[[:xdigit:]]{64}$ ]] || {
    echo "MCP_DBPASS must be 64 hexadecimal characters" >&2
    return 1
  }

  encryption_key="$(mcp_config_value "${config_path}" MCP_ENCRYPTION_KEY)" || {
    echo "MCP_ENCRYPTION_KEY must be set exactly once" >&2
    return 1
  }
  [[ "${encryption_key}" =~ ^[[:xdigit:]]{64}$ ]] || {
    echo "MCP_ENCRYPTION_KEY must be 64 hexadecimal characters" >&2
    return 1
  }

  profiles="$(mcp_config_value "${config_path}" COMPOSE_PROFILES)" || {
    echo "COMPOSE_PROFILES must be set exactly once" >&2
    return 1
  }
  if [[ "${state}" == "enabled" ]] && ! mcp_profile_contains "${profiles}" mcp; then
    echo "MCP is enabled but COMPOSE_PROFILES does not contain mcp" >&2
    return 1
  fi
  if [[ "${state}" == "disabled" ]] && mcp_profile_contains "${profiles}" mcp; then
    echo "MCP is disabled but COMPOSE_PROFILES contains mcp" >&2
    return 1
  fi

  local default_key
  local -a default_keys=(
    MCP_UPDATE_OFFERED
    MCP_DBNAME
    MCP_DBUSER
    MCP_OAUTH_ALLOWED_REDIRECT_URIS
    MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS
    MCP_ATTACHMENT_MAX_BYTES
    MCP_MESSAGE_MAX_BYTES
    MCP_BASE64_UPLOAD_MAX_BYTES
    MCP_UPLOAD_TTL_SECONDS
    MCP_ATTACHMENT_ALLOWED_TYPES
    MCP_LOGIN_ATTEMPTS
    MCP_LOGIN_WINDOW_SECONDS
    MCP_REGISTRATIONS_PER_HOUR
    MCP_REQUESTS_PER_MINUTE
    MCP_SENDS_PER_MINUTE
    MCP_RECIPIENTS_PER_HOUR
    MCP_CONCURRENT_UPLOADS
    MCP_AUDIT_RETENTION_DAYS
  )
  for default_key in "${default_keys[@]}"; do
    mcp_config_value "${config_path}" "${default_key}" >/dev/null || {
      echo "${default_key} must be set exactly once" >&2
      return 1
    }
  done

  [[ "$(mcp_config_value "${config_path}" MCP_UPDATE_OFFERED)" =~ ^[01]$ ]] || {
    echo "MCP_UPDATE_OFFERED must be 0 or 1" >&2
    return 1
  }
}

mcp_append_if_missing() {
  local config_path="$1"
  local key="$2"
  local value="$3"

  mcp_config_has_key "${config_path}" "${key}" || printf '%s=%s\n' "${key}" "${value}" >> "${config_path}"
}

mcp_append_defaults() {
  local config_path="$1"
  local install_type="$2"

  mcp_append_if_missing "${config_path}" COMPOSE_PROFILES ""
  mcp_append_if_missing "${config_path}" MCP_UPDATE_OFFERED "$([[ "${install_type}" == "new" ]] && printf 1 || printf 0)"
  mcp_append_if_missing "${config_path}" MCP_DBNAME mailcow_mcp
  mcp_append_if_missing "${config_path}" MCP_DBUSER mailcow_mcp
  mcp_append_if_missing "${config_path}" MCP_OAUTH_ALLOWED_REDIRECT_URIS 'https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback'
  mcp_append_if_missing "${config_path}" MCP_OAUTH_ALLOW_LOOPBACK_REDIRECTS 1
  mcp_append_if_missing "${config_path}" MCP_ATTACHMENT_MAX_BYTES 10485760
  mcp_append_if_missing "${config_path}" MCP_MESSAGE_MAX_BYTES 26214400
  mcp_append_if_missing "${config_path}" MCP_BASE64_UPLOAD_MAX_BYTES 1048576
  mcp_append_if_missing "${config_path}" MCP_UPLOAD_TTL_SECONDS 3600
  mcp_append_if_missing "${config_path}" MCP_ATTACHMENT_ALLOWED_TYPES pdf,xlsx,csv,txt,png,jpg,jpeg
  mcp_append_if_missing "${config_path}" MCP_LOGIN_ATTEMPTS 5
  mcp_append_if_missing "${config_path}" MCP_LOGIN_WINDOW_SECONDS 900
  mcp_append_if_missing "${config_path}" MCP_REGISTRATIONS_PER_HOUR 10
  mcp_append_if_missing "${config_path}" MCP_REQUESTS_PER_MINUTE 120
  mcp_append_if_missing "${config_path}" MCP_SENDS_PER_MINUTE 10
  mcp_append_if_missing "${config_path}" MCP_RECIPIENTS_PER_HOUR 100
  mcp_append_if_missing "${config_path}" MCP_CONCURRENT_UPLOADS 5
  mcp_append_if_missing "${config_path}" MCP_AUDIT_RETENTION_DAYS 30
}

mcp_prepare_config() {
  local config_path="$1"
  local install_type="$2"
  local config_dir
  local config_name
  local profiles
  local validation_state
  local config_versioned=n

  [[ -f "${config_path}" ]] || {
    echo "MCP configuration file is missing" >&2
    return 1
  }
  [[ "${install_type}" == "new" || "${install_type}" == "upgrade" ]] || {
    echo "MCP installation type must be new or upgrade" >&2
    return 1
  }

  mcp_config_has_key "${config_path}" MCP_CONFIG_VERSION && config_versioned=y

  config_dir="$(dirname "${config_path}")"
  config_name="$(basename "${config_path}")"

  (
    local temp_config
    local temp_config_escaped
    local generated_secret

    umask 077
    temp_config="$(mktemp "${config_dir}/.${config_name}.mcp.XXXXXX")" || exit 1
    printf -v temp_config_escaped '%q' "${temp_config}"
    trap "rm -f -- ${temp_config_escaped}" EXIT
    cp "${config_path}" "${temp_config}" || exit 1

    mcp_append_defaults "${temp_config}" "${install_type}"

    if [[ "${config_versioned}" == n ]]; then
      if mcp_config_has_key "${temp_config}" MCP_DBPASS; then
        mcp_config_value "${temp_config}" MCP_DBPASS >/dev/null || exit 1
      else
        generated_secret="$(LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
        printf 'MCP_DBPASS=%s\n' "${generated_secret}" >> "${temp_config}"
      fi
      if mcp_config_has_key "${temp_config}" MCP_ENCRYPTION_KEY; then
        mcp_config_value "${temp_config}" MCP_ENCRYPTION_KEY >/dev/null || exit 1
      else
        generated_secret="$(LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
        printf 'MCP_ENCRYPTION_KEY=%s\n' "${generated_secret}" >> "${temp_config}"
      fi
      printf 'MCP_CONFIG_VERSION=1\n' >> "${temp_config}"
    fi
    chmod 600 "${temp_config}" || exit 1
    profiles="$(mcp_config_value "${temp_config}" COMPOSE_PROFILES)" || exit 1
    if mcp_profile_contains "${profiles}" mcp; then
      validation_state=enabled
    else
      validation_state=disabled
    fi
    mcp_validate_config "${temp_config}" "${validation_state}" || exit 1
    mv "${temp_config}" "${config_path}" || exit 1
  )
}
