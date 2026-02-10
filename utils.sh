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

validate_tool_availability() {
  local input_tool=$1

  if ! command -v $1 &>/dev/null; then
    echo -e "\n[${RED}✗${NC}] ${RED}\"${input_tool}\" is not installed. Install it first.${NC}"
    exit 1
  fi
}

validate_file_availability() {
  local input_file=$1

  if [[ ! -f "$input_file" ]]; then
    echo -e "\n[${RED}${ERROR_SYM}${NC}] ${RED}File \"$input_file\" not found!${NC}"
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

  if ! compgen -G "${glob_pattern}" >/dev/null; then
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
  local success_msg="${3:-$wait_msg successfully completed}"
  local error_msg="${4:-$wait_msg failed}"

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

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"

  mkdir -p "${TEMP_DIR}"
  local regex_patterns="${TEMP_DIR}/patterns.tmp"

  cat "${filters_dir}"/*.json | jq -r '.[]' > "${regex_patterns}"

  if [ -f "${whitelist_file}" ] && [ -s "${whitelist_file}" ]; then
     awk -v wlist="$whitelist_file" -v blist="$regex_patterns" '
       BEGIN {
         while((getline < wlist) > 0) whitelist[$0]=1
       }
       {
         if ($0 in whitelist) {
           print $0
         } else {
           print $0 | "rg -v -N -f " blist
         }
       }
     ' "${input_file}" | sort -uV > "${TEMP_DIR}/pre_trimmed.tmp"

  else
     rg -v -N -f "${regex_patterns}" "${input_file}" | sort -uV > "${TEMP_DIR}/pre_trimmed.tmp"
  fi

  awk -F. '!/^#/ && NF {
      if (NF >= 2) print $(NF-1)"."$NF; else print $0
  }' "${TEMP_DIR}/pre_trimmed.tmp" | sort -uV > "${output_file}"

  rm -f "${regex_patterns}" "${TEMP_DIR}/pre_trimmed.tmp"
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
  }' "${input_file}" | sort -uV >"${output_file}"
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

  if ((${#files[@]} == 0)); then
    echo -e "[${RED}${ERROR_SYM}${NC}] There are no files with the .lst extension in the \"$input_dir\" folder" >&2
    exit 1
  fi

  validate_file_dir "${output_file}"

  if rg -m 1 '^[^#]' "${files[0]}" | rg -qP '^[0-9./\r]+$'; then
    cat "${files[@]}" \
    | rg -v '^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' \
    | mapcidr -silent -a -o "${output_file}" >/dev/null
  else
    sort -uV "${files[@]}" > "${output_file}"
  fi
}

merge_hosts() {
  local input_dir="$1"
  local output_file="$2"
  local sni_proxy_ip_file="${ROOT_DIR}/sni-proxy-ips.lst"

  validate_file_availability "${sni_proxy_ip_file}"
  validate_file_dir "${output_file}"

  rg -IN . "$input_dir" -g "*.lst" | \
  awk -v ip_file="$sni_proxy_ip_file" '
    BEGIN {
      while ((getline < ip_file) > 0) {
        if ($0 ~ /^[0-9.]+$/) ips[ip_count++] = $0
      }
      close(ip_file)
      if (ip_count == 0) { print "No valid IPs found!" > "/dev/stderr"; exit 1 }
      srand()
    }

    {
      sub(/#.*/, "")
      gsub(/^[ \t]+|[ \t]+$/, "")
      if (length($0) == 0) next

      $0 = tolower($0)

      if ($0 ~ /^(0\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$)/) next
      if ($0 !~ /^([a-z0-9-]+\.)+[a-z]{2,}$/) next

      n = split($0, parts, ".")
      root = (n >= 2) ? parts[n-1] "." parts[n] : "misc"

      if (!seen[$0]++) {
          groups[root] = (groups[root] == "") ? $0 : groups[root] " " $0
      }
    }

    END {
      for (g in groups) {
        random_ip = ips[int(rand() * ip_count)]
        print random_ip " " groups[g]
      }
    }
  ' > "$output_file"
}

add_localhost() {
  local input_file=$1
  local output_file=$2

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"

  echo "127.0.0.1 localhost" >"${output_file}"
  echo "::1 localhost ip6-localhost ip6-loopback" >>"${output_file}"
  echo "ff02::1 ip6-allnodes" >>"${output_file}"
  echo "ff02::2 ip6-allrouters" >>"${output_file}"
  echo "" >>"${output_file}"
  cat "${input_file}" >>"${output_file}"
}

fetch_cdn_ip_ranges() {
  local output_file=$1

  validate_file_dir "${output_file}"
  validate_tool_availability "cdn-ranges"

  cdn-ranges -v4 -output "${output_file}" >/dev/null
}

combine_hosts() {
  local input_file=$1
  local output_file=$2

  validate_file_availability "${input_file}"
  validate_file_dir "${output_file}"
  validate_tool_availability "rg"

  awk '
    { sub(/#.*/, "") }
    /^\s*$/ { next }
    /^(0\.|127\.|::1)/ { next }
    { print }
  ' "${input_file}" > "${output_file}"
}
