#!/usr/bin/env bash

source ./utils.sh

TEMP_FOLDER="${ROOT_DIR}/temp"
LIST_FOLDER="${ROOT_DIR}/lists"
PLAIN_LIST_FOLDER="${LIST_FOLDER}/plain"
SING_BOX_LIST_FOLDER="${LIST_FOLDER}/sing-box"
HOSTS_LIST_FOLDER="${LIST_FOLDER}/hosts"

ANTIFILTER_DOMAINLIST="https://antifilter.download/list/domains.lst"
ANTIFILTER_COMMUNITY_DOMAINLIST="https://community.antifilter.download/list/domains.lst"
RE_FILTER_DOMAINLIST="https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst"

ANTIFILTER_IPSET="https://antifilter.download/list/allyouneed.lst"
ANTIFILTER_EXTRA_IPSET="https://antifilter.download/list/ipresolve.lst"
ANTIFILTER_COMMUNITY_IPSET="https://community.antifilter.download/list/community.lst"
RE_FILTER_IPSET="https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst"

CDN_IP_RANGES="https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt"

MALW_HOSTS="https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"
ITDOGINFO_GEOBLOCK="https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Categories/geoblock.lst"

setup() {
  rm -rf "${LIST_FOLDER}"
}

cleanup() {
  rm -f "${ROOT_DIR}/resume.cfg"
  rm -rf "${TEMP_FOLDER}"
}

main() {
  setup

  # --- Domains ---
  download "${ANTIFILTER_DOMAINLIST}" "${TEMP_FOLDER}/domains/antifilter.lst" &
  domain_download_pid=$!

  download "${ANTIFILTER_COMMUNITY_DOMAINLIST}" "${TEMP_FOLDER}/domains/antifilter-community.lst" &
  community_domain_download_pid=$!

  download "${RE_FILTER_DOMAINLIST}" "${TEMP_FOLDER}/domains/re-filter.lst" &
  re_filter_domain_download_pid=$!

  spinner "${domain_download_pid}" "Antifilter domain list downloading" || return 1
  spinner "${community_domain_download_pid}" "Antifilter Community domain list downloading" || return 1
  spinner "${re_filter_domain_download_pid}" "Re:filter domain list downloading" || return 1

  merge_lists "${TEMP_FOLDER}/domains" "${PLAIN_LIST_FOLDER}/domains/full.lst" &
  spinner $! "Domains merging" || return 1

  cleanup_domains "${PLAIN_LIST_FOLDER}/domains/full.lst" "${PLAIN_LIST_FOLDER}/domains/full-sld.lst" &
  spinner $! "Domains filtering and optimization" || return 1

  # --- IPSets ---
  download "${ANTIFILTER_IPSET}" "${TEMP_FOLDER}/ipsets/antifilter.lst" &
  antifilter_ipset_download_pid=$!

  download "${ANTIFILTER_COMMUNITY_IPSET}" "${TEMP_FOLDER}/ipsets/antifilter-community.lst" &
  community_ipset_download_pid=$!

  download "${ANTIFILTER_EXTRA_IPSET}" "${TEMP_FOLDER}/ipsets/antifilter-extra.lst" &
  extra_ipset_download_pid=$!

  download "${RE_FILTER_IPSET}" "${TEMP_FOLDER}/ipsets/re-filter.lst" &
  re_filter_ipset_download_pid=$!

  spinner "${antifilter_ipset_download_pid}" "Antifilter IPSet downloading" || return 1
  spinner "${community_ipset_download_pid}" "Antifilter Community IPSet downloading" || return 1
  spinner "${extra_ipset_download_pid}" "Antifilter Extra IPSet downloading" || return 1
  spinner "${re_filter_ipset_download_pid}" "Re:filter IPSet downloading" || return 1

  merge_lists "${TEMP_FOLDER}/ipsets" "${PLAIN_LIST_FOLDER}/ipsets/full.lst" &
  spinner $! "IPSets merging" || return 1

  # --- Hosts ---
  download "${MALW_HOSTS}" "${TEMP_FOLDER}/hosts/malw-hosts.lst" &
  malw_hosts_download_pid=$!

  download "${ITDOGINFO_GEOBLOCK}" "${TEMP_FOLDER}/hosts/itdoginfo-geoblock.lst" &
  itdoginfo_hosts_download_pid=$!

  spinner "${malw_hosts_download_pid}" "ImMALWARE's hosts downloading" || return 1
  spinner "${itdoginfo_hosts_download_pid}" "ItDogInfo's geoblock domains downloading" || return 1

  merge_hosts "${TEMP_FOLDER}/hosts" "${HOSTS_LIST_FOLDER}/combined.lst" &
  spinner $! "Hosts merging and processing" || return 1

  add_localhost "${HOSTS_LIST_FOLDER}/combined.lst" "${HOSTS_LIST_FOLDER}/ready-to-use.lst" &
  spinner $! "Hosts localhost addition" || return 1

  # --- CDN IP Ranges ---
  download "${CDN_IP_RANGES}" "${PLAIN_LIST_FOLDER}/ipsets/cdn.lst" &
  spinner $! "CDN IP Ranges downloading" || return 1

  cat "${PLAIN_LIST_FOLDER}/ipsets/cdn.lst" \
    "${PLAIN_LIST_FOLDER}/ipsets/full.lst" \
    | mapcidr -silent -a -o "${PLAIN_LIST_FOLDER}/ipsets/full-and-cdn.lst" >/dev/null &
  spinner $! "CDN IP Ranges and blocked ipset merging" || return 1

  # --- sing-box rule-sets ---
  generate_sing_box_ruleset \
    "domain" \
    "${PLAIN_LIST_FOLDER}/domains/full.lst" \
    "${SING_BOX_LIST_FOLDER}/domains/full.json" \
    "${SING_BOX_LIST_FOLDER}/domains/full.srs" &
  spinner $! "sing-box full domain rule-set generation" || return 1

  generate_sing_box_ruleset \
    "domain_suffix" \
    "${PLAIN_LIST_FOLDER}/domains/full-sld.lst" \
    "${SING_BOX_LIST_FOLDER}/domains/full-sld.json" \
    "${SING_BOX_LIST_FOLDER}/domains/full-sld.srs" &
  spinner $! "sing-box domain suffix rule-set generation" || return 1

  generate_sing_box_ruleset \
    "ip_cidr" \
    "${PLAIN_LIST_FOLDER}/ipsets/full.lst" \
    "${SING_BOX_LIST_FOLDER}/ipsets/full.json" \
    "${SING_BOX_LIST_FOLDER}/ipsets/full.srs" &
  spinner $! "sing-box full ipset rule-set generation" || return 1

  generate_sing_box_ruleset \
    "ip_cidr" \
    "${PLAIN_LIST_FOLDER}/ipsets/full-and-cdn.lst" \
    "${SING_BOX_LIST_FOLDER}/ipsets/full-and-cdn.json" \
    "${SING_BOX_LIST_FOLDER}/ipsets/full-and-cdn.srs" &
  spinner $! "sing-box merged ipset rule-set generation" || return 1

  echo -e "[${GREEN}${SUCCESS_SYM}${NC}] ${BOLD}${GREEN}Process completed!${NC}"

  cleanup
}

main
