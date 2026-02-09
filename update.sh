#!/usr/bin/env bash

source ./utils.sh

TEMP_FOLDER="${ROOT_DIR}/temp"
LIST_FOLDER="${ROOT_DIR}/lists"

ANTIFILTER_DOMAINLIST="https://antifilter.download/list/domains.lst"
ANTIFILTER_COMMUNITY_DOMAINLIST="https://community.antifilter.download/list/domains.lst"
RE_FILTER_DOMAINLIST="https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst"

ANTIFILTER_IPSET="https://antifilter.download/list/allyouneed.lst"
ANTIFILTER_EXTRA_IPSET="https://antifilter.download/list/ipresolve.lst"
ANTIFILTER_COMMUNITY_IPSET="https://community.antifilter.download/list/community.lst"
RE_FILTER_IPSET="https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/ipsum.lst"

CDN_IP_RANGES="https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all_plain_ipv4.txt"

MALW_HOSTS="https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"
MAFIOZNIK_HOSTS="https://freedom.mafioznik.xyz/file/hosts"
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
  spinner $! "Antifilter domain list downloading"

  download "${ANTIFILTER_COMMUNITY_DOMAINLIST}" "${TEMP_FOLDER}/domains/antifilter-community.lst" &
  spinner $! "Antifilter Community domain list downloading"

  download "${RE_FILTER_DOMAINLIST}" "${TEMP_FOLDER}/domains/re-filter.lst" &
  spinner $! "Re:filter domain list downloading"

  merge_lists "${TEMP_FOLDER}/domains" "${LIST_FOLDER}/domains/full.lst" &
  spinner $! "Domains merging"

  cleanup_domains "${LIST_FOLDER}/domains/full.lst" "${LIST_FOLDER}/domains/full-smart.lst" &
  spinner $! "Domains filtering and optimization"

  # --- IPSets ---
  download "${ANTIFILTER_IPSET}" "${TEMP_FOLDER}/ipsets/antifilter.lst" &
  spinner $! "Antifilter IPSet downloading"

  download "${ANTIFILTER_COMMUNITY_IPSET}" "${TEMP_FOLDER}/ipsets/antifilter-community.lst" &
  spinner $! "Antifilter Community IPSet downloading"

  download "${ANTIFILTER_EXTRA_IPSET}" "${TEMP_FOLDER}/ipsets/antifilter-extra.lst" &
  spinner $! "Antifilter Extra IPSet downloading"

  download "${RE_FILTER_IPSET}" "${TEMP_FOLDER}/ipsets/re-filter.lst" &
  spinner $! "Re:filter IPSet downloading"

  merge_lists "${TEMP_FOLDER}/ipsets" "${LIST_FOLDER}/ipsets/full.lst" &
  spinner $! "IPSets merging"

  optimize_ipset "${LIST_FOLDER}/ipsets/full.lst" "${LIST_FOLDER}/ipsets/full-smart.lst" &
  spinner $! "IPSet optimization"

  # --- Hosts ---
  download "${MALW_HOSTS}" "${TEMP_FOLDER}/hosts/malw-hosts.lst" &
  spinner $! "ImMALWARE's hosts downloading"

  download "${MAFIOZNIK_HOSTS}" "${TEMP_FOLDER}/hosts/mafioznik-hosts.lst" &
  spinner $! "Mafioznik's hosts downloading"

  download "${ITDOGINFO_GEOBLOCK}" "${TEMP_FOLDER}/hosts/itdoginfo-geoblock.lst" &
  spinner $! "ItDogInfo's geoblock domains downloading"

  merge_hosts "${TEMP_FOLDER}/hosts" "${LIST_FOLDER}/hosts/combined.lst" &
  spinner $! "Hosts merging and processing"

  add_localhost "${LIST_FOLDER}/hosts/combined.lst" "${LIST_FOLDER}/hosts/ready-to-use.lst" &
  spinner $! "Hosts localhost addition"

  # --- CDN IP Ranges ---
  download "${CDN_IP_RANGES}" "${LIST_FOLDER}/ipsets/cdn.lst" &
  spinner $! "CDN IP Ranges downloading"

  cat "${LIST_FOLDER}/ipsets/cdn.lst" \
    "${LIST_FOLDER}/ipsets/full-smart.lst" \
    | mapcidr -silent -a -o "${LIST_FOLDER}/ipsets/full-smart-and-cdn.lst" >/dev/null &
  spinner $! "CDN IP Ranges and blocked ipset merging"

  echo -e "[${GREEN}${SUCCESS_SYM}${NC}] ${BOLD}${GREEN}Process completed!${NC}"

  cleanup
}

main
