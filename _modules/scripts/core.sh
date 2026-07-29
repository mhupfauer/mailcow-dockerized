#!/usr/bin/env bash
# _modules/scripts/core.sh
# THIS SCRIPT IS DESIGNED TO BE RUNNING BY MAILCOW SCRIPTS ONLY!
# DO NOT, AGAIN, NOT TRY TO RUN THIS SCRIPT STANDALONE!!!!!!

# ANSI color for red errors
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
LIGHT_RED='\e[91m'
LIGHT_GREEN='\e[92m'
NC='\e[0m'

caller="${BASH_SOURCE[1]##*/}"
MCP_UPDATE_CORE_SERVICES=()

mcp_update_config_path() {
  printf '%s\n' "${MAILCOW_CONF:-${SCRIPT_DIR}/mailcow.conf}"
}

mcp_update_mark_offered() (
  local config_path
  local config_dir
  local temp_config
  local profiles
  local state

  config_path="$(mcp_update_config_path)"
  config_dir="$(dirname "${config_path}")"
  umask 077
  temp_config="$(mktemp "${config_dir}/.mailcow.conf.mcp-offer.XXXXXX")" || return 1
  if ! awk '
    BEGIN { count = 0 }
    /^MCP_UPDATE_OFFERED=/ {
      print "MCP_UPDATE_OFFERED=1"
      count++
      next
    }
    { print }
    END { if (count != 1) exit 1 }
  ' "${config_path}" > "${temp_config}"; then
    rm -f -- "${temp_config}"
    return 1
  fi
  chmod 600 "${temp_config}" || {
    rm -f -- "${temp_config}"
    return 1
  }
  profiles="$(mcp_config_value "${temp_config}" COMPOSE_PROFILES)" || {
    rm -f -- "${temp_config}"
    return 1
  }
  if mcp_profile_contains "${profiles}" mcp; then
    state=enabled
  else
    state=disabled
  fi
  mcp_validate_config "${temp_config}" "${state}" || {
    rm -f -- "${temp_config}"
    return 1
  }
  mv -- "${temp_config}" "${config_path}"
)

mcp_update_preflight() {
  local config_path
  local profiles

  config_path="$(mcp_update_config_path)"
  profiles="$(mcp_config_value "${config_path}" COMPOSE_PROFILES)" || {
    echo -e "${LIGHT_RED}Could not determine whether MCP is enabled; refusing the update.${NC}" >&2
    return 1
  }
  MCP_UPDATE_AVAILABLE=n
  if mcp_profile_contains "${profiles}" mcp; then
    MCP_UPDATE_ENABLED=y
    if ! mcp_prepare_config "${config_path}" upgrade; then
      echo -e "${LIGHT_RED}Enabled MCP configuration preparation failed before update.${NC}" >&2
      return 1
    fi
    mcp_validate_config "${config_path}" enabled || return 1
  else
    MCP_UPDATE_ENABLED=n
    if ! mcp_prepare_config "${config_path}" upgrade; then
      echo -e "${YELLOW}Disabled MCP configuration is unavailable; preserving it and continuing the core update.${NC}" >&2
      return 0
    fi
    mcp_validate_config "${config_path}" disabled || return 1
  fi
  MCP_UPDATE_AVAILABLE=y
}

mcp_update_offer() {
  local config_path
  local offered
  local profiles
  local response

  [[ "${MCP_UPDATE_AVAILABLE:-y}" == y ]] || return 0
  config_path="$(mcp_update_config_path)"
  offered="$(mcp_config_value "${config_path}" MCP_UPDATE_OFFERED)" || return 1
  [[ "${offered}" == 0 ]] || return 0
  profiles="$(mcp_config_value "${config_path}" COMPOSE_PROFILES)" || return 1
  if mcp_profile_contains "${profiles}" mcp; then
    echo "MCP is already enabled; no adoption prompt is needed"
    mcp_update_mark_offered
    return
  fi

  if [[ -n "${FORCE:-}" || "${SKIP_START:-}" == y || ! -t 0 ]]; then
    echo "MCP remains disabled. Enable it later with ./helper-scripts/mcp.sh enable"
    mcp_update_mark_offered
    return
  fi

  read -r -p "Enable the optional mailcow MCP service now? [y/N] " response
  if [[ "${response}" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    if ! "${SCRIPT_DIR}/helper-scripts/mcp.sh" enable; then
      MCP_UPDATE_ACTIVATION_FAILED=y
      echo -e "${LIGHT_RED}MCP activation failed; core mailcow remains available.${NC}" >&2
    fi
  else
    echo "MCP remains disabled. Enable it later with ./helper-scripts/mcp.sh enable"
  fi
  mcp_update_mark_offered
}

mcp_update_load_core_services() {
  local service_output
  local service
  local found_nginx=n
  local found_postfix=n

  MCP_UPDATE_CORE_SERVICES=()
  if ! service_output="$(
    unset COMPOSE_PROFILES
    $COMPOSE_COMMAND config --services
  )"; then
    echo -e "${LIGHT_RED}Could not derive the core mailcow Compose services.${NC}" >&2
    return 1
  fi
  while IFS= read -r service; do
    [[ -n "${service}" ]] || continue
    if [[ ! "${service}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
      echo -e "${LIGHT_RED}Compose returned an invalid service name.${NC}" >&2
      return 1
    fi
    case "${service}" in
      mcp-db-init|mcp-mailcow) continue ;;
      nginx-mailcow) found_nginx=y ;;
      postfix-mailcow) found_postfix=y ;;
    esac
    MCP_UPDATE_CORE_SERVICES+=("${service}")
  done <<< "${service_output}"

  if [[ ${#MCP_UPDATE_CORE_SERVICES[@]} -eq 0 ||
        "${found_nginx}" != y || "${found_postfix}" != y ]]; then
    echo -e "${LIGHT_RED}Derived core service set is incomplete; refusing partial startup.${NC}" >&2
    return 1
  fi
}

mcp_update_pull_core() {
  if [[ ${#MCP_UPDATE_CORE_SERVICES[@]} -eq 0 ]]; then
    mcp_update_load_core_services || return 1
  fi
  (
    unset COMPOSE_PROFILES
    $COMPOSE_COMMAND pull "${MCP_UPDATE_CORE_SERVICES[@]}"
  )
}

mcp_update_start_core() {
  if [[ ${#MCP_UPDATE_CORE_SERVICES[@]} -eq 0 ]]; then
    mcp_update_load_core_services || return 1
  fi
  if (
    unset COMPOSE_PROFILES
    $COMPOSE_COMMAND up -d --remove-orphans "${MCP_UPDATE_CORE_SERVICES[@]}"
  ); then
    MCP_UPDATE_CORE_STARTED=y
    return 0
  fi
  MCP_UPDATE_CORE_FAILED=y
  return 1
}

mcp_update_report() {
  local config_path
  local profiles

  config_path="$(mcp_update_config_path)"
  profiles="$(mcp_config_value "${config_path}" COMPOSE_PROFILES 2>/dev/null || true)"
  if [[ -n "${MCP_UPDATE_CORE_FAILED:-}" ]]; then
    echo -e "${LIGHT_RED}Core mailcow startup failed. MCP adoption was not offered.${NC}"
    return 1
  elif [[ -n "${MCP_UPDATE_ACTIVATION_FAILED:-}" ||
          -n "${MCP_UPDATE_MCP_FAILED:-}" ]]; then
    echo -e "${LIGHT_RED}MCP services failed, but core mailcow started independently.${NC}"
    echo "Retry MCP with ./helper-scripts/mcp.sh retry"
  elif [[ "${MCP_UPDATE_AVAILABLE:-y}" != y ]]; then
    echo -e "${YELLOW}MCP configuration is unavailable; core mailcow was updated without MCP adoption.${NC}"
    echo "Repair the MCP settings before running ./helper-scripts/mcp.sh enable"
  elif mcp_profile_contains "${profiles}" mcp; then
    echo "MCP remains enabled. Check it with ./helper-scripts/mcp.sh status"
  else
    echo "MCP is disabled. Enable it with ./helper-scripts/mcp.sh enable"
  fi
}

get_installed_tools(){
    for bin in openssl curl docker git awk sha1sum grep cut jq; do
        if [[ -z $(command -v ${bin}) ]]; then
          echo "Error: Cannot find command '${bin}'. Cannot proceed."
          echo "Solution: Please review system requirements and install requirements. Then, re-run the script."
          echo "See System Requirements: https://docs.mailcow.email/getstarted/install/"
          echo "Exiting..."
          exit 1
        fi
    done

    if grep --help 2>&1 | head -n 1 | grep -q -i "busybox"; then echo -e "${LIGHT_RED}BusyBox grep detected, please install gnu grep, \"apk add --no-cache --upgrade grep\"${NC}"; exit 1; fi
    # This will also cover sort
    if cp --help 2>&1 | head -n 1 | grep -q -i "busybox"; then echo -e "${LIGHT_RED}BusyBox cp detected, please install coreutils, \"apk add --no-cache --upgrade coreutils\"${NC}"; exit 1; fi
    if sed --help 2>&1 | head -n 1 | grep -q -i "busybox"; then echo -e "${LIGHT_RED}BusyBox sed detected, please install gnu sed, \"apk add --no-cache --upgrade sed\"${NC}"; exit 1; fi
}

get_docker_version(){
    # Check Docker Version (need at least 24.X)
    docker_version=$(docker version --format '{{.Server.Version}}' | cut -d '.' -f 1)
}

get_compose_type(){
  if docker compose > /dev/null 2>&1; then
    if docker compose version --short | grep -e "^[2-9]\." -e "^v[2-9]\." -e "^[1-9][0-9]\." -e "^v[1-9][0-9]\." > /dev/null 2>&1; then
      COMPOSE_VERSION=native
      COMPOSE_COMMAND="docker compose"
      if [[ "$caller" == "update.sh" ]]; then
        sed -i 's/^DOCKER_COMPOSE_VERSION=.*/DOCKER_COMPOSE_VERSION=native/' "$SCRIPT_DIR/mailcow.conf"
      fi
      echo -e "\e[33mFound Docker Compose Plugin (native).\e[0m"
      echo -e "\e[33mSetting the DOCKER_COMPOSE_VERSION Variable to native\e[0m"
      sleep 2
      echo -e "\e[33mNotice: You'll have to update this Compose Version via your Package Manager manually!\e[0m"
    else
      echo -e "\e[31mCannot find Docker Compose with a Version Higher than 2.X.X.\e[0m"
      echo -e "\e[31mPlease update/install it manually regarding to this doc site: https://docs.mailcow.email/install/\e[0m"
      exit 1
    fi
  elif docker-compose > /dev/null 2>&1; then
  if ! [[ $(alias docker-compose 2> /dev/null) ]] ; then
    if docker-compose version --short | grep -e "^[2-9]\." -e "^[1-9][0-9]\." > /dev/null 2>&1; then
      COMPOSE_VERSION=standalone
      COMPOSE_COMMAND="docker-compose"
      if [[ "$caller" == "update.sh" ]]; then
        sed -i 's/^DOCKER_COMPOSE_VERSION=.*/DOCKER_COMPOSE_VERSION=standalone/' "$SCRIPT_DIR/mailcow.conf"
      fi
      echo -e "\e[33mFound Docker Compose Standalone.\e[0m"
      echo -e "\e[33mSetting the DOCKER_COMPOSE_VERSION Variable to standalone\e[0m"
      sleep 2
      echo -e "\e[33mNotice: For an automatic update of docker-compose please use the update_compose.sh scripts located at the helper-scripts folder.\e[0m"
    else
      echo -e "\e[31mCannot find Docker Compose with a Version Higher than 2.X.X.\e[0m"
      echo -e "\e[31mPlease update/install manually regarding to this doc site: https://docs.mailcow.email/install/\e[0m"
      exit 1
    fi
  fi
  else
    echo -e "\e[31mCannot find Docker Compose.\e[0m"
    echo -e "\e[31mPlease install it regarding to this doc site: https://docs.mailcow.email/install/\e[0m"
    exit 1
  fi
}

detect_bad_asn() {
  echo -e "\e[33mDetecting if your IP is listed on Spamhaus Bad ASN List...\e[0m"
  response=$(curl --connect-timeout 15 --max-time 30 -s -o /dev/null -w "%{http_code}" "https://asn-check.mailcow.email")
  if [ "$response" -eq 503 ]; then
    if [ -z "$SPAMHAUS_DQS_KEY" ]; then
      echo -e "\e[33mYour server's public IP uses an AS that is blocked by Spamhaus to use their DNS public blocklists for Postfix.\e[0m"
      echo -e "\e[33mmailcow did not detected a value for the variable SPAMHAUS_DQS_KEY inside mailcow.conf!\e[0m"
      sleep 2
      echo ""
      echo -e "\e[33mTo use the Spamhaus DNS Blocklists again, you will need to create a FREE account for their Data Query Service (DQS) at: https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account\e[0m"
      echo -e "\e[33mOnce done, enter your DQS API key in mailcow.conf and mailcow will do the rest for you!\e[0m"
      echo ""
      sleep 2
    else
      echo -e "\e[33mYour server's public IP uses an AS that is blocked by Spamhaus to use their DNS public blocklists for Postfix.\e[0m"
      echo -e "\e[32mmailcow detected a Value for the variable SPAMHAUS_DQS_KEY inside mailcow.conf. Postfix will use DQS with the given API key...\e[0m"
    fi
  elif [ "$response" -eq 200 ]; then
    echo -e "\e[33mCheck completed! Your IP is \e[32mclean\e[0m"
  elif [ "$response" -eq 429 ]; then
    echo -e "\e[33mCheck completed! \e[31mYour IP seems to be rate limited on the ASN Check service... please try again later!\e[0m"
  else
    echo -e "\e[31mCheck failed! \e[0mMaybe a DNS or Network problem?\e[0m"
  fi
}

check_online_status() {
  CHECK_ONLINE_DOMAINS=('https://github.com' 'https://hub.docker.com')
  for domain in "${CHECK_ONLINE_DOMAINS[@]}"; do
    if timeout 6 curl --head --silent --output /dev/null ${domain}; then
      return 0
    fi
  done
  return 1
}

prefetch_images() {
  [[ -z ${BRANCH} ]] && { echo -e "\e[33m\nUnknown branch...\e[0m"; exit 1; }
  git fetch origin #${BRANCH}
  while read image; do
    RET_C=0
    until docker pull "${image}"; do
      RET_C=$((RET_C + 1))
      echo -e "\e[33m\nError pulling $image, retrying...\e[0m"
      [ ${RET_C} -gt 3 ] && { echo -e "\e[31m\nToo many failed retries, exiting\e[0m"; exit 1; }
      sleep 1
    done
  done < <(git show "origin/${BRANCH}:docker-compose.yml" | grep "image:" | awk '{ gsub("image:","", $3); print $2 }')
}

docker_garbage() {
  SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )"
  IMGS_TO_DELETE=()

  declare -A IMAGES_INFO
  # Match any registry namespace the compose file uses - upstream ghcr.io/mailcow,
  # a fork republishing under ghcr.io/<owner>, or the legacy bare mailcow/ names -
  # so forks still get their superseded image tags cleaned up.
  COMPOSE_IMAGES=($(grep -oP "image: \K((ghcr\.io/[^/]+/)|mailcow/)[^[:space:]]+" "${SCRIPT_DIR}/docker-compose.yml"))

  [[ -z ${COMPOSE_IMAGES[*]} ]] && return 0

  # Only ever consider repositories the compose file actually references, so an
  # unrelated image sharing the fork's namespace is never swept up.
  COMPOSE_REPOS=($(printf '%s\n' "${COMPOSE_IMAGES[@]}" | sed 's|:[^:]*$||' | sort -u))

  for existing_image in $(docker images --format "{{.ID}}:{{.Repository}}:{{.Tag}}"); do
      ID=$(echo "$existing_image" | cut -d ':' -f 1)
      REPOSITORY=$(echo "$existing_image" | cut -d ':' -f 2)
      TAG=$(echo "$existing_image" | cut -d ':' -f 3)

      if [[ ! " ${COMPOSE_REPOS[*]} " =~ " ${REPOSITORY} " ]]; then
          continue
      fi

      if [[ "$REPOSITORY" == "mailcow/backup" || "$REPOSITORY" == */backup ]]; then
          if [[ "$TAG" != "<none>" ]]; then
              continue
          fi
      fi

      if [[ " ${COMPOSE_IMAGES[@]} " =~ " ${REPOSITORY}:${TAG} " ]]; then
          continue
      else
          IMGS_TO_DELETE+=("$ID")
          IMAGES_INFO["$ID"]="$REPOSITORY:$TAG"
      fi
  done

  if [[ ! -z ${IMGS_TO_DELETE[*]} ]]; then
      echo "The following unused mailcow images were found:"
      for id in "${IMGS_TO_DELETE[@]}"; do
          echo "    ${IMAGES_INFO[$id]} ($id)"
      done

      if [ -z "$FORCE" ]; then
          read -r -p "Do you want to delete them to free up some space? [y/N] " response
          if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
              docker rmi ${IMGS_TO_DELETE[*]}
          else
              echo "OK, skipped."
          fi
      else
          echo "Running in forced mode! Force removing old mailcow images..."
          docker rmi ${IMGS_TO_DELETE[*]}
      fi
      echo -e "\e[32mFurther cleanup...\e[0m"
      echo "If you want to cleanup further garbage collected by Docker, please make sure all containers are up and running before cleaning your system by executing \"docker system prune\""
  fi
}

in_array() {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

detect_major_update() {
  if [ ${BRANCH} == "master" ]; then
    # Array with major versions
    # Add major versions here
    MAJOR_VERSIONS=(
      "2025-02"
      "2025-03"
      "2025-09"
    )

    current_version=""
    if [[ -f "${SCRIPT_DIR}/data/web/inc/app_info.inc.php" ]]; then
      current_version=$(grep 'MAILCOW_GIT_VERSION' ${SCRIPT_DIR}/data/web/inc/app_info.inc.php | sed -E 's/.*MAILCOW_GIT_VERSION="([^"]+)".*/\1/')
    fi
    if [[ -z "$current_version" ]]; then
      return 1
    fi
    release_url="https://github.com/mailcow/mailcow-dockerized/releases/tag"

    updates_to_apply=()

    for version in "${MAJOR_VERSIONS[@]}"; do
      if [[ "$current_version" < "$version" ]]; then
        updates_to_apply+=("$version")
      fi
    done

    if [[ ${#updates_to_apply[@]} -gt 0 ]]; then
      echo -e "\e[33m\nMAJOR UPDATES to be applied:\e[0m"
      for update in "${updates_to_apply[@]}"; do
        echo "$update - $release_url/$update"
      done

      echo -e "\nPlease read the release notes before proceeding."
      read -p "Do you want to proceed with the update? [y/n] " response
      if [[ "${response}" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
        echo "Proceeding with the update..."
      else
        echo "Update canceled. Exiting."
        exit 1
      fi
    fi
  fi
}
