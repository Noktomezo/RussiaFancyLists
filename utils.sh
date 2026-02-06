#!/usr/bin/env bash

export LC_ALL=C
export LANG=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="${ROOT_DIR}/temp"

SUCCESS_SYM="✓"
WARNING_SYM="⚠"
ERROR_SYM="✗"

RED=$(printf '\033[31m')
GREEN=$(printf '\033[32m')
YELLOW=$(printf '\033[33m')
NC=$(printf '\033[0m')
BOLD=$(printf '\033[1m')
BLUE=$(printf '\033[34m')
UNBOLD=$(printf '\033[22m')
DIM=$(printf '\033[2m')

validate_tool_availaibility() {
  local input_tool=$1

  if ! command -v $1 &> /dev/null; then
    echo -e "\n[${RED}✗${NC}] ${RED}\"${input_tool}\" is not installed. Install it first.${NC}"
    exit 1
  fi
}

validate_file_availability() {
  local input_file=$1

  if [[ ! -f "$input_file" ]]; then
      echo -e "\n[${RED}${ERROR_SYM}${NC}] ${RED} File \"$input_file\" not found!"
      exit 1
  fi
}

validate_file_dir() {
    local input_file=$1

    local output_dir=$(dirname "${input_file}")
    mkdir -p "${output_dir}"
}

validate_files_by_pattern() {
  local glob_pattern=$1

  if ! compgen -G "${glob_pattern}" > /dev/null; then
      echo "\n[${YELLOW}${WARNING_SYM}${NC}] No files matching \"${glob_pattern}\" pattern found." >&2
      return 1
  else
      return 0
  fi
}

cleanup_spinner() {
    printf "\033[?25h" # Restore cursor
    exit 1
}

spinner() {
    local pid=$1
    local wait_msg=$2
    local success_msg="${3:-\"$wait_msg\" successfully completed}"
    local error_msg="${4:-\"$wait_msg\" failed}"

    # validate if stdout is a terminal (TTY)
    if [[ ! -t 1 ]]; then
        printf "[RUNNING] %s...\n" "$wait_msg"

        wait "$pid"
        local exit_status=$?

        if [ $exit_status -eq 0 ]; then
            printf "[%s] %s\n" "$SUCCESS_SYM" "$success_msg"
        else
            printf "[%s] %s (exit code: %s)\n" "$ERROR_SYM" "$error_msg" "$exit_status"
        fi
        return $exit_status
    fi

    local spinstr='|/-\\'
    local delay=0.1
    local i=0

    # Hide cursor and setup trap for unexpected exits
    printf "\033[?25l"
    trap cleanup_spinner SIGINT SIGTERM

    while kill -0 "$pid" 2>/dev/null; do
        local frame="${spinstr:$i:1}"
        printf "\r[%b%s%b] %b%s%b" "${YELLOW}" "${frame}" "${NC}" "${YELLOW}" "${wait_msg}" "${NC}"
        ((i = (i + 1) % ${#spinstr}))
        sleep "$delay"
    done

    wait "$pid"
    local exit_status=$?

    # Clear the spinner line and restore cursor
    printf "\r\033[K"
    printf "\033[?25h"
    trap - SIGINT SIGTERM # Reset trap

    if [ $exit_status -eq 0 ]; then
        printf "%b[%b%s%b%b] %b%s%b\n" "${DIM}" "${GREEN}" "$SUCCESS_SYM" "${NC}" "${DIM}" "${GREEN}" "${success_msg}" "${NC}"
    else
        printf "[%b%s%b] %b%s%b (exit code: %s)\n" "${RED}" "$ERROR_SYM" "${NC}" "${RED}" "${error_msg}" "${NC}" "$exit_status"
    fi

    return $exit_status
}

download() {
    local url="$1"
    local output_file="${2:-}"

    local args=(--retry 5 --retry-delay 2 --retry-all-errors --insecure -fsSL)

    if [[ -n "${output_file}" ]]; then
        validate_file_dir "${output_file}"
        curl "${args[@]}" -o "$output_file" "$url"
    else
        curl "${args[@]}" "$url"
    fi
}


cleanup_domains() {
  local input_file=$1
  local output_file=$2

  local filters_dir="filters"
  local whitelist_file="filters/whitelist.txt"

  mkdir -p "${TEMP_DIR}"
  local regex_patterns="${TEMP_DIR}/patterns.tmp"
  local safe_domains="${TEMP_DIR}/safe.tmp"
  local to_scan="${TEMP_DIR}/to_scan.tmp"
  local clean_scanned="${TEMP_DIR}/scanned_clean.tmp"

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"
  validate_tool_availaibility "rg"

  cat "${filters_dir}"/*.json | jq -r '.[]' > "${regex_patterns}"

  if [ -f "${whitelist_file}" ] && [ -s "${whitelist_file}" ]; then
    rg -F -x -f "${whitelist_file}" "${input_file}" > "${safe_domains}"
    rg -v -F -x -f "${whitelist_file}" "${input_file}" > "${to_scan}"
  else
    touch "${safe_domains}"
    touch "${to_scan}"
    cp "${input_file}" "${to_scan}"
  fi

  rg -v -N -f "${regex_patterns}" "${to_scan}" > "${clean_scanned}"
  cat "${safe_domains}" "${clean_scanned}" > "${output_file}"
  local trimmed="${TEMP_DIR}/trimmed.tmp"
  trim_sub_domains "${output_file}" "${trimmed}"
  mv "${trimmed}" "${output_file}"
  rm "${regex_patterns}" "${safe_domains}" "${to_scan}" "${clean_scanned}"
}

trim_sub_domains() {
  local input_file=$1
  local output_file=$2

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"

  awk -F. '!/^#/ && NF {
    if (NF >= 2) {
        print $(NF-1)"."$NF
    } else {
        print $0
    }
  }' "${input_file}" | sort -uV > "${output_file}"
}

merge_lists() {
    local input_dir="$1"
    local output_file="$2"

    if [[ ! -d "${input_dir}" ]]; then
        echo -e "[${RED}${ERROR_SYM}${NC}] ${RED}Directory \"${input_dir}\" not found.${NC}" >&2
        exit 1
    fi

    shopt -s nullglob
    local files=("${input_dir}"/*.lst)
    shopt -u nullglob

    if (( ${#files[@]} == 0 )); then
        echo -e "[${RED}${ERROR_SYM}${NC}] There are no files with the .lst extension in the \"$input_dir\" folder" >&2
        exit 1
    fi

    validate_file_dir "${output_file}"
    sort -uV "${files[@]}" > "${output_file}"
}

merge_hosts() {
    local input_dir="$1"
    local output_file="$2"

    if [[ ! -d "${input_dir}" ]]; then
        echo -e "[${RED}${ERROR_SYM}${NC}] ${RED}Directory \"${input_dir}\" not found.${NC}" >&2
        exit 1
    fi

    shopt -s nullglob
    local files=("${input_dir}"/*.lst)
    shopt -u nullglob

    if (( ${#files[@]} == 0 )); then
        echo -e "[${RED}${ERROR_SYM}${NC}] There are no files with the .lst extension in the \"$input_dir\" folder" >&2
        exit 1
    fi

    validate_file_dir "${output_file}"
    sed 's/#.*//' "${files[@]}" \
        | tr -d '\r' \
        | rg -v '^(#|0\.0\.0\.0|127\.0\.0\.1|::1)|^\s*$' \
        | awk '!seen[$2]++' \
        | sort -k2 \
        > "${output_file}"
}

add_localhost() {
  local input_file=$1
  local output_file=$2

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"

  echo "127.0.0.1 localhost" > "${output_file}"
  echo "::1 localhost ip6-localhost ip6-loopback" >> "${output_file}"
  echo "ff02::1 ip6-allnodes" >> "${output_file}"
  echo "ff02::2 ip6-allrouters" >> "${output_file}"
  echo "" >> "${output_file}"
  cat "${input_file}" >> "${output_file}"
}

fetch_cdn_ip_ranges() {
  local output_file=$1

  validate_file_dir "${output_file}"
  validate_tool_availaibility "cdn-ranges"

  cdn-ranges -v4 -output "${output_file}"
}

resolve_domains() {
  local input_file=$1
  local output_file=$2

  local dns_resolver_file="${ROOT_DIR}/resolvers.txt"

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"
  validate_tool_availaibility "dnsx"

  if ! command -v ulimit &> /dev/null ; then
    ulimit -n 100000
  fi

  dnsx \
    -list="${input_file}" \
    -resolver="${dns_resolver_file}" \
    -threads=500 \
    -resp \
    -silent \
    -no-color \
    -output="${output_file}" \
    >/dev/null
}

parse_resolvable_meta() {
  local input_file="$1"
  local ipset_output="$2"
  local hostlist_output="$3"
  
  validate_file_availability "${input_file}"
  validate_file_dir "${ipset_output}"
  validate_file_dir "${hostlist_output}"

  awk -v host_out="$hostlist_output" -v ip_out="$ipset_output" '{
    print $1 >> host_out
    gsub(/[\[\]]/, "", $3)
    print $3 | "sort -uV > \"" ip_out "\""
  }' "${input_file}"
}

optimize_domains() {
  local input_file=$1
  local output_file=$2

  validate_file_availability "${input_file}"
  trim_sub_domains "${input_file}" "${output_file}"
}

optimize_ipset() {
  local input_file=$1
  local output_file=$2

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"
  validate_tool_availaibility "iprange"

  rg -v '^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' "${input_file}" | iprange --optimize - > "${output_file}"
}

combine_hosts() {
  local input_file=$1
  local output_file=$2

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"

  rg -v '^(#|0\.0\.0\.0|127\.0\.0\.1|::1)' "${input_file}" | rg -v '^$' > "${output_file}"
}
