#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#   WRAITH — DNS Passive Recon Scanner v1.2.0
#   Author  : romandoro
#   GitHub  : github.com/romandoro/wraith
# ═══════════════════════════════════════════════════════════════════
#   Usage:
#     bash wraith.sh <start-ip> <end-ip>  [options]
#     bash wraith.sh <cidr/prefix>        [options]
#   Options:
#     -t <n>   Workers per phase  (default: 3, Termux: ≤ 5)
#     -T <n>   Timeout per query  (default: 3s)
#     -r <ip>  Custom resolver    (default: system)
#     -o <dir> Output base dir    (default: ./wraith_scans)
#     -R       Resume last scan of same range
#     -X       Phase 3: AXFR zone transfer  ⚠ NS logs this
#     -h       Help
# ═══════════════════════════════════════════════════════════════════

set -uo pipefail   # -e omitted: DNS failures are expected

# ── Globals ───────────────────────────────────────────────────────
readonly VERSION="1.2.0"
THREADS=3; TIMEOUT=3; RESOLVER=""
OUTPUT_BASE="./wraith_scans"; RESUME=0; AXFR_ENABLED=0
START_NUM=0; END_NUM=0; DISP_PID=""

# ── Palette ───────────────────────────────────────────────────────
PRI=$'\e[38;5;39m'   # bright cyan   – accents, borders
SEC=$'\e[38;5;75m'   # steel cyan    – hostnames
G=$'\e[38;5;77m'     # soft green    – success / MATCH
Y=$'\e[38;5;179m'    # muted amber   – warning / MISMATCH
ER=$'\e[38;5;167m'   # muted coral   – errors
W=$'\e[1;37m'        # bold white    – values
D=$'\e[2;37m'        # dim grey      – decorations
N=$'\e[0m'           # reset

# ── Temp dir ─────────────────────────────────────────────────────
WDIR="$(mktemp -d "${TMPDIR:-/tmp}/wraith_XXXXXX")"

cleanup() {
    { exec 8>&- 9>&-; } 2>/dev/null || true
    [[ -n "${DISP_PID:-}" ]] && kill "$DISP_PID" 2>/dev/null || true
    rm -rf "$WDIR"
}
trap cleanup EXIT
trap 'printf "\n${ER}[!]${N} Interrupted\n"; exit 130' INT TERM

# ── Banner ────────────────────────────────────────────────────────
banner() {
    printf "${PRI}"
    cat << 'BANNER'

  ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
  ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
  ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
  ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
  ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
BANNER
    printf "${N}"
    printf "  ${D}DNS Passive Recon  ·  v${VERSION}${N}\n"
    printf "  ${D}Author : ${W}romandoro${N}  ${D}·  github.com/${W}romandoro${N}/wraith\n"
    printf "  ${PRI}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n\n"
}

# ── Log helpers ───────────────────────────────────────────────────
log_info()  { printf "  ${D}[${W}·${D}]${N}  %s\n"  "$*"; }
log_ok()    { printf "  ${D}[${G}✓${D}]${N}  %s\n"  "$*"; }
log_warn()  { printf "  ${D}[${Y}!${D}]${N}  %s\n"  "$*" >&2; }
log_err()   { printf "  ${D}[${ER}✗${D}]${N}  %s\n" "$*" >&2; }
log_phase() { printf "\n  ${PRI}┌─${N} ${W}%s${N}\n" "$*"; }

# ── Status bar ────────────────────────────────────────────────────
# Uses \033[2K (erase full line) + \r to cleanly overwrite.
# Bar width adapts to COLUMNS so it doesn't wrap on narrow screens.
_draw_status() {
    local done=$1 total=$2 label=$3 found=$4
    (( total <= 0 )) && return
    local cols="${COLUMNS:-$(tput cols 2>/dev/null || echo 70)}"
    # Overhead without bar: "  │  []  100%  254/254 A-REC  ✦254" = 34 visual chars
    # cols-36 (34+2 safety) ensures bar never wraps on narrow phone screens
    local w=$(( cols - 36 ))
    (( w < 4  )) && w=4
    (( w > 26 )) && w=26
    local filled=$(( done * w / total )) pct=$(( done * 100 / total ))
    local bar="" i
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=filled; i<w;  i++ )); do bar+="░"; done
    printf "\r\033[2K  ${D}│${N}  ${PRI}[${bar}]${N}  ${W}%3d%%${N}  ${D}%d/%d %s${N}  ${G}✦%d${N}" \
        "$pct" "$done" "$total" "$label" "$found"
}

# ── Display manager ───────────────────────────────────────────────
# FIFO protocol (fd 8):
#   F|ip<TAB>hostname      PTR finding → scroll above status bar
#   A|ip<TAB>host<TAB>a_ip<TAB>status  A-record result
#   D|                     done counter increment
#
# FIX: reader started BEFORE exec 8>"$fifo" to avoid open() deadlock.
# FIX: exec 8>&- called BEFORE wait so display manager receives EOF
#      and exits naturally — avoiding the "hung at 100%" issue.
start_display() {
    local total=$1 label=$2 phase=$3   # phase: ptr | a
    local fifo="${WDIR}/ctrl.fifo"
    rm -f "$fifo"; mkfifo "$fifo"

    local _t="$total" _l="$label" _p="$phase"

    # ── Reader first (prevents open() blocking on write end) ──────
    (
        found=0; match_n=0; done_n=0

        while IFS='|' read -r cmd data; do
            case "$cmd" in
                F)  # PTR finding: ip<TAB>hostname
                    ip_f="${data%%$'\t'*}"; host_f="${data#*$'\t'}"
                    # Erase status bar line, print finding, next _draw_status
                    # appears on the fresh line below — gobuster pattern
                    printf '\r\033[2K'
                    printf "  ${PRI}╞${N}  ${W}%-18s${N}  ${D}→${N}  ${SEC}%s${N}\n" \
                        "$ip_f" "$host_f"
                    (( ++found ))
                    ;;
                A)  # A-record: ip<TAB>host<TAB>a_ip<TAB>status
                    # done_n++ here — no separate D| sent for Phase 2
                    status_a="${data##*$'\t'}"
                    case "$status_a" in
                        MATCH)
                            (( ++match_n ))
                            ;;
                        MISMATCH)
                            # Real anomaly — different IP returned, display it
                            ip_a="${data%%$'\t'*}"
                            r="${data#*$'\t'}"; host_a="${r%%$'\t'*}"
                            r="${r#*$'\t'}";   a_ip_a="${r%%$'\t'*}"
                            printf '\r\033[2K'
                            printf "  ${Y}╞${N}  %-18s  ${Y}%-28s  %-16s  %s${N}\n" \
                                "$ip_a" "$host_a" "$a_ip_a" "$status_a"
                            ;;
                        NORESOLVE)
                            # ISP noise — PTR exists but no forward A, silent
                            ;;
                    esac
                    (( ++done_n ))
                    ;;
                D)  (( ++done_n )) ;;
            esac
            if [[ "$_p" == "ptr" ]]; then
                _draw_status "$done_n" "$_t" "$_l" "$found"
            else
                _draw_status "$done_n" "$_t" "$_l" "$match_n"
            fi
        done

        # Final bar at 100%
        printf '\r\033[2K'
        if [[ "$_p" == "ptr" ]]; then
            _draw_status "$_t" "$_t" "$_l" "$found"
        else
            _draw_status "$_t" "$_t" "$_l" "$match_n"
        fi
        printf '\n'
    ) < "$fifo" &
    DISP_PID=$!

    # ── Writer end opened AFTER reader is waiting ─────────────────
    exec 8>"$fifo"
}

# Close write end BEFORE wait so display manager receives EOF naturally.
# Then plain `wait` handles both PTR jobs AND display manager.
stop_display() {
    exec 8>&- 2>/dev/null || true  # EOF → display manager exits
    wait 2>/dev/null || true       # wait for all background jobs
    DISP_PID=""
    rm -f "${WDIR}/ctrl.fifo"
}

# ── IP utilities ──────────────────────────────────────────────────
validate_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.' oct o; read -ra o <<< "$ip"
    for oct in "${o[@]}"; do
        [[ "${#oct}" -gt 1 && "${oct:0:1}" == "0" ]] && return 1
        (( 10#$oct <= 255 )) || return 1
    done
}

ip_to_num() {
    local IFS='.' o; read -ra o <<< "$1"
    printf '%d' "$(( (o[0]<<24) + (o[1]<<16) + (o[2]<<8) + o[3] ))"
}

num_to_ip() {    # outputs IP + newline; $() callers strip it automatically
    local n=$1
    printf '%d.%d.%d.%d\n' \
        "$(( (n>>24)&255 ))" "$(( (n>>16)&255 ))" \
        "$(( (n>>8) &255 ))" "$(( n     &255 ))"
}

cidr_to_range() {
    local cidr="$1"
    local ip="${cidr%/*}" pfx="${cidr#*/}"
    validate_ipv4 "$ip" || { log_err "Invalid CIDR host: $ip"; return 1; }
    [[ "$pfx" =~ ^[0-9]+$ ]] && (( pfx >= 1 && pfx <= 32 )) \
        || { log_err "Invalid prefix: /$pfx"; return 1; }
    local n mask net bcast
    n=$(ip_to_num "$ip")
    (( pfx == 32 )) && mask=4294967295 \
                    || mask=$(( (0xFFFFFFFF << (32-pfx)) & 0xFFFFFFFF ))
    net=$(( n & mask )); bcast=$(( net | (~mask & 0xFFFFFFFF) ))
    if (( pfx <= 30 )); then START_NUM=$(( net+1 )); END_NUM=$(( bcast-1 ))
    else                     START_NUM=$net;         END_NUM=$bcast; fi
}

make_scan_id() {   # 185.124.45.1-254_20260917-2008 style
    local sip="$1" eip="$2" ts="$3"
    if [[ "${sip%.*}" == "${eip%.*}" ]]; then
        printf '%s-%s_%s' "$sip" "${eip##*.}" "$ts"
    else
        printf '%s-%s_%s' "$sip" "$eip" "$ts"
    fi
}

# ── Semaphore ─────────────────────────────────────────────────────
sem_init() {
    mkfifo "${WDIR}/sem.fifo"
    exec 9<>"${WDIR}/sem.fifo"
    local i; for (( i=0; i<THREADS; i++ )); do printf '\n' >&9; done
}
sem_acquire() { IFS= read -r -u 9 _; }
sem_release() { printf '\n' >&9; }

# ── DNS core ─────────────────────────────────────────────────────
build_dig() {
    printf '%s\n' "dig" "-r"   # -r: ignore ~/.digrc
    [[ -n "$RESOLVER" ]] && printf '@%s\n' "$RESOLVER"
    printf '%s\n' "$@"
    printf '%s\n' "+time=${TIMEOUT}" "+tries=1" "+short"
}

run_dig() {   # if/fi avoids (A&&B)||C re-running dig without timeout
    local hard=$(( TIMEOUT + 3 ))
    if command -v timeout &>/dev/null; then
        timeout "$hard" "$@"
    else
        "$@"
    fi
}

ptr_query() {
    local ip="$1"
    local -a cmd; readarray -t cmd < <(build_dig -x "$ip")
    local result
    result=$(run_dig "${cmd[@]}" 2>/dev/null \
        | grep -v '^;;' \
        | sed 's/\.$//' \
        | grep -Ev '^[[:space:]]*$' \
        | head -1) || true
    [[ -n "$result" ]] && printf '%s\t%s' "$ip" "$result"
}

a_query() {
    local orig_ip="$1" hostname="$2"
    local -a cmd; readarray -t cmd < <(build_dig A "$hostname")
    local a_ip
    a_ip=$(run_dig "${cmd[@]}" 2>/dev/null \
        | grep -v '^;;' \
        | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
        | head -1) || true
    if   [[ -z "$a_ip" ]];            then printf '%s\t%s\t-\tNORESOLVE' "$orig_ip" "$hostname"
    elif [[ "$a_ip" == "$orig_ip" ]]; then printf '%s\t%s\t%s\tMATCH'    "$orig_ip" "$hostname" "$a_ip"
    else                                   printf '%s\t%s\t%s\tMISMATCH' "$orig_ip" "$hostname" "$a_ip"
    fi
}

wildcard_check() {
    local s=$1 e=$2 probe_num probe_ip
    (( e < 4294967295 )) && probe_num=$(( e+1 )) || probe_num=$(( s-1 ))
    probe_ip=$(num_to_ip "$probe_num")
    local -a cmd; readarray -t cmd < <(build_dig -x "$probe_ip")
    run_dig "${cmd[@]}" 2>/dev/null \
        | grep -v '^;;' | sed 's/\.$//' \
        | grep -Ev '^[[:space:]]*$' | head -1 || true
}

extract_domains() {
    [[ -f "$1" ]] || return
    awk -F'\t' 'NF>=2 && $2!="" {
        n=split($2,a,"."); if(n>=2) print a[n-1]"."a[n]
    }' "$1" | sort -u
}

# ── AXFR (Phase 3) ────────────────────────────────────────────────
# For each domain: query NS records, then try AXFR against each NS.
# A successful transfer has SOA at start+end → record count > 2.
# AXFR uses TCP automatically; no +short (we want full output).
axfr_domain() {
    local domain="$1" scan_dir="$2"

    # Get NS servers for this domain
    local -a ns_list
    readarray -t ns_list < <(
        dig -r +short NS "$domain" "+time=${TIMEOUT}" +tries=1 2>/dev/null \
        | grep -v '^;;' | sed 's/\.$//' | grep -Ev '^[[:space:]]*$'
    ) || true

    if (( ${#ns_list[@]} == 0 )); then
        printf "  ${D}    No NS records for %s${N}\n" "$domain"
        return 0
    fi

    local vuln_count=0 ns ns_ip axfr_out rec_count

    for ns in "${ns_list[@]}"; do
        # Resolve NS hostname → IP
        if [[ "$ns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ns_ip="$ns"
        else
            ns_ip=$(dig -r +short A "$ns" "+time=${TIMEOUT}" +tries=1 2>/dev/null \
                | grep -v '^;;' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1) || true
            [[ -z "$ns_ip" ]] && ns_ip="$ns"
        fi

        printf "  ${D}  ╞${N}  ${W}%-28s${N}  ${D}@${N}  ${SEC}%-18s${N}  " "$domain" "$ns_ip"

        # AXFR — TCP used automatically, longer timeout
        axfr_out=$(timeout $(( TIMEOUT * 6 )) dig -r AXFR "$domain" "@${ns_ip}" 2>/dev/null) || true

        # Count real DNS records (non-comment lines)
        rec_count=$(printf '%s\n' "$axfr_out" \
            | grep -cv '^[;[:space:]]') 2>/dev/null || rec_count=0
        rec_count=$(( rec_count + 0 ))

        # Successful transfer: SOA at start+end → at least 2 SOA + records > 2 total
        if (( rec_count > 2 )) && printf '%s\n' "$axfr_out" | grep -q 'IN[[:space:]]SOA'; then
            (( ++vuln_count ))
            printf "${G}VULNERABLE  ${W}%d records${N}\n" "$rec_count"

            # Save full zone to file
            local out_file="${scan_dir}/axfr_${domain//./_}.txt"
            {
                printf '# WRAITH AXFR — %s\n' "$domain"
                printf '# Nameserver : %s (%s)\n' "$ns" "$ns_ip"
                printf '# Records    : %d\n' "$rec_count"
                printf '# Timestamp  : %s\n' "$(date '+%Y-%m-%d %H:%M')"
                printf '# ─────────────────────────────────────────────\n'
                printf '%s\n' "$axfr_out"
            } > "$out_file"

            # Preview: first 8 interesting records
            printf '%s\n' "$axfr_out" \
                | grep -E 'IN[[:space:]]+(A|AAAA|MX|NS|TXT|CNAME|SRV)[[:space:]]' \
                | head -8 \
                | while IFS= read -r rec; do
                    printf "  ${D}      │  ${SEC}%s${N}\n" "$rec"
                done
        else
            # Determine denial reason
            local reason="REFUSED"
            if   printf '%s\n' "$axfr_out" | grep -qi 'Transfer failed'; then reason="FAILED"
            elif printf '%s\n' "$axfr_out" | grep -qi 'NOTAUTH';         then reason="NOTAUTH"
            elif printf '%s\n' "$axfr_out" | grep -qi 'SERVFAIL';        then reason="SERVFAIL"
            elif [[ -z "$axfr_out" ]];                                    then reason="TIMEOUT/REFUSED"
            fi
            printf "${D}✗  %s${N}\n" "$reason"
        fi
    done

    return "$vuln_count"
}

# ── Results table ─────────────────────────────────────────────────
print_results_table() {
    local hf="$1"; [[ -s "$hf" ]] || return
    awk -F'\t' \
        -v PRI="$PRI" -v SEC="$SEC" -v G="$G" \
        -v Y="$Y"     -v W="$W"     -v D="$D" -v N="$N" \
    '
    NR==FNR {
        l1=(length($1)>l1)?length($1):l1
        l2=(length($2)>l2)?length($2):l2
        l3=(length($3)>l3)?length($3):l3
        next
    }
    FNR==1 {
        c1=(l1<15)?15:l1; c2=(l2<28)?28:l2; c3=(l3<15)?15:l3
        # content width: 2+c1+2+c2+2+c3+2+10+2 = c1+c2+c3+20
        sep=""
        for(i=0; i<c1+c2+c3+20; i++) sep=sep"─"
        printf "\n  " D "╭" sep "╮" N "\n"
        printf "  " D "│" N "  %-*s  %-*s  %-*s  %-10s  " D "│" N "\n",
            c1, W"IP"N, c2, W"HOSTNAME"N, c3, W"A-RECORD"N, W"FCrDNS"N
        printf "  " D "├" sep "┤" N "\n"
    }
    {
        col=($4=="MATCH")?G:($4=="MISMATCH")?Y:D
        printf "  " D "│" N "  %-*s  " SEC "%-*s" N "  %-*s  %s%-10s" N "  " D "│" N "\n",
            c1, $1, c2, $2, c3, $3, col, $4
    }
    END { printf "  " D "╰" sep "╯" N "\n" }
    ' "$hf" "$hf"
}

# ── File listing ──────────────────────────────────────────────────
file_size() {
    local b; b=$(( $(wc -c < "$1" 2>/dev/null || echo 0) + 0 ))
    (( b < 1024 ))    && { printf '%d B'  "$b"; return; }
    (( b < 1048576 )) && { printf '%d KB' "$(( b/1024 ))"; return; }
    printf '%d MB' "$(( b/1048576 ))"
}

print_files() {
    local scan_dir="$1"
    printf "\n  ${D}Output${N}  ${W}%s${N}\n" "$scan_dir"
    local -a names=("ips.txt" "ptrs.tsv" "hosts.tsv" "domains.txt" "summary.txt")
    # Also include any AXFR files
    while IFS= read -r axf; do
        names+=("$(basename "$axf")")
    done < <(ls "${scan_dir}"/axfr_*.txt 2>/dev/null || true)

    local i last=$(( ${#names[@]} - 1 ))
    for i in "${!names[@]}"; do
        local f="${scan_dir}/${names[$i]}"
        [[ -f "$f" ]] || continue
        local pfx="${D}├──${N}"; (( i == last )) && pfx="${D}└──${N}"
        printf "  %s  ${W}%-24s${N}  ${D}%s${N}\n" "$pfx" "${names[$i]}" "$(file_size "$f")"
    done
}

# ── Misc ──────────────────────────────────────────────────────────
check_deps() {
    local fail=0 dep
    for dep in dig awk sed; do
        command -v "$dep" &>/dev/null || {
            log_err "Missing: $dep  →  pkg install dnsutils"; (( ++fail )); }
    done
    (( fail == 0 )) || exit 1
}

android_warn() {
    local ver; ver=$(getprop ro.build.version.release 2>/dev/null) || return 0
    [[ "$ver" =~ ^([0-9]+) ]] || return 0
    (( BASH_REMATCH[1] >= 12 && THREADS > 5 )) && \
        log_warn "Android ${ver}: phantom process limit — recommend -t ≤ 5"
}

find_resume_dir() {
    ls -1d "${OUTPUT_BASE}/${1}-"* 2>/dev/null | sort -r | head -1
}

# ── Usage ─────────────────────────────────────────────────────────
usage() {
    banner
    printf "  ${W}USAGE${N}\n"
    printf "    %s  <start-ip> <end-ip>   [options]\n"  "$0"
    printf "    %s  <cidr>                [options]\n\n" "$0"
    printf "  ${W}OPTIONS${N}\n"
    printf "    ${PRI}-t <n>${N}    Workers per phase   (default: ${W}3${N})\n"
    printf "    ${PRI}-T <n>${N}    Timeout per query   (default: ${W}3${N}s)\n"
    printf "    ${PRI}-r <ip>${N}   Custom resolver\n"
    printf "    ${PRI}-o <dir>${N}  Output base dir     (default: ${W}./wraith_scans${N})\n"
    printf "    ${PRI}-R${N}        Resume last scan of same range\n"
    printf "    ${PRI}-X${N}        Phase 3: AXFR zone transfer  ${Y}⚠ NS logs this${N}\n"
    printf "    ${PRI}-h${N}        Help\n\n"
    printf "  ${W}EXAMPLES${N}\n"
    printf "    %s  192.168.1.1 192.168.1.90\n"       "$0"
    printf "    %s  10.0.0.0/24 -t 4 -r 8.8.8.8\n"    "$0"
    printf "    %s  192.168.1.0/24 -X\n\n"            "$0"
}

# ── Argument parsing ──────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && { usage; exit 0; }
    [[ "${1:-}" =~ ^(-h|--help)$ ]] && { usage; exit 0; }

    if [[ "$1" == *"/"* ]]; then
        cidr_to_range "$1" || exit 1; shift
    else
        [[ $# -lt 2 ]] && { log_err "Need <start-ip> <end-ip> or <CIDR>"; exit 1; }
        validate_ipv4 "$1" || { log_err "Invalid start IP: $1"; exit 1; }
        validate_ipv4 "$2" || { log_err "Invalid end IP:   $2"; exit 1; }
        START_NUM=$(ip_to_num "$1"); END_NUM=$(ip_to_num "$2")
        (( START_NUM <= END_NUM )) || { log_err "Start IP > End IP"; exit 1; }
        shift 2
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t) THREADS="$2"
                [[ "$THREADS" =~ ^[0-9]+$ ]] && (( THREADS>=1 && THREADS<=20 )) \
                    || { log_err "-t must be 1–20"; exit 1; }
                shift 2 ;;
            -T) TIMEOUT="$2"
                [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { log_err "-T must be integer"; exit 1; }
                shift 2 ;;
            -r) RESOLVER="$2"
                validate_ipv4 "$RESOLVER" || { log_err "Bad resolver: $RESOLVER"; exit 1; }
                shift 2 ;;
            -o) OUTPUT_BASE="$2"; shift 2 ;;
            -R) RESUME=1; shift ;;
            -X) AXFR_ENABLED=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) log_err "Unknown: $1"; exit 1 ;;
        esac
    done
}

# ── Main ──────────────────────────────────────────────────────────
main() {
    banner
    check_deps
    parse_args "$@"
    android_warn

    local range=$(( END_NUM - START_NUM + 1 ))
    local start_ip end_ip
    start_ip=$(num_to_ip "$START_NUM")
    end_ip=$(num_to_ip   "$END_NUM")

    local ts; ts=$(date '+%Y%m%d-%H%M')
    local scan_id; scan_id=$(make_scan_id "$start_ip" "$end_ip" "$ts")
    local scan_dir

    if (( RESUME )); then
        local prev; prev=$(find_resume_dir "$start_ip")
        if [[ -n "$prev" ]]; then
            scan_dir="$prev"; log_info "Resuming : ${W}${scan_dir}${N}"
        else
            log_warn "No previous scan found — starting fresh"
            scan_dir="${OUTPUT_BASE}/${scan_id}"; RESUME=0
        fi
    else
        scan_dir="${OUTPUT_BASE}/${scan_id}"
    fi
    mkdir -p "$scan_dir"

    log_info "Range    : ${W}${start_ip}${N} → ${W}${end_ip}${N}  (${W}${range}${N} addresses)"
    [[ -n "$RESOLVER" ]] && log_info "Resolver : ${W}${RESOLVER}${N}" \
                         || log_info "Resolver : ${D}system${N}"
    log_info "Threads  : ${W}${THREADS}${N}  ·  Timeout: ${W}${TIMEOUT}${N}s"
    log_info "Output   : ${W}${scan_dir}${N}"
    (( AXFR_ENABLED )) && log_warn "AXFR enabled — Phase 3 will attempt zone transfers"

    if (( range > 1024 )); then
        log_warn "Large range: ${range} addresses"
        printf "  Continue? [y/N] "; read -r _ans
        [[ "$_ans" =~ ^[Yy]$ ]] || { printf "Aborted.\n"; exit 0; }
    fi

    # ── Wildcard check ────────────────────────────────────────────
    log_phase "Wildcard PTR check"
    local wc_result; wc_result=$(wildcard_check "$START_NUM" "$END_NUM")
    if [[ -n "$wc_result" ]]; then
        log_warn "WILDCARD PTR detected → '${wc_result}' (results may be synthetic)"
    else
        log_ok "No wildcard PTR"
    fi

    # ── Generate IP list ──────────────────────────────────────────
    local ip_file="${scan_dir}/ips.txt"
    if (( RESUME )) && [[ -f "$ip_file" ]]; then
        log_info "Using existing ips.txt"
    else
        log_phase "Generating IP list"
        local i
        for (( i=START_NUM; i<=END_NUM; i++ )); do num_to_ip "$i"; done > "$ip_file"
        log_ok "${range} addresses → ips.txt"
    fi

    sem_init

    # ── Phase 1: PTR ──────────────────────────────────────────────
    log_phase "Phase 1 — PTR queries  [${THREADS} workers · ${TIMEOUT}s]"

    local ptr_file="${scan_dir}/ptrs.tsv"
    local scan_ip_file="$ip_file"
    local effective_range=$range

    if (( RESUME )) && [[ -f "$ptr_file" ]]; then
        cut -f1 "$ptr_file" | sort > "$WDIR/done_ips.txt"
        sort "$ip_file" | comm -23 - "$WDIR/done_ips.txt" > "$WDIR/remaining.txt"
        effective_range=$(( $(wc -l < "$WDIR/remaining.txt") + 0 ))
        if (( effective_range > 0 )); then
            log_info "Resume: ${effective_range} IPs remaining"
            scan_ip_file="$WDIR/remaining.txt"
        else
            log_ok "PTR phase already complete"; effective_range=0
        fi
    else
        : > "$ptr_file"
    fi

    if (( effective_range > 0 )); then
        start_display "$effective_range" "PTR" "ptr"
        while read -r ip; do
            sem_acquire
            (
                result=$(ptr_query "$ip")
                if [[ -n "$result" ]]; then
                    printf '%s\n' "$result" >> "$ptr_file"
                    printf 'F|%s\n' "$result" >&8
                fi
                printf 'D|\n' >&8
                sem_release
            ) &
        done < "$scan_ip_file"
        # FIX: close fd 8 BEFORE wait → display manager receives EOF
        # and exits naturally while we wait; no deadlock at 100%
        exec 8>&-
        wait
        DISP_PID=""
        rm -f "${WDIR}/ctrl.fifo"
    fi

    local ptr_count
    ptr_count=$(( $(wc -l < "$ptr_file" 2>/dev/null || echo 0) + 0 ))
    log_ok "PTR records : ${W}${ptr_count}${N}"

    # ── Phase 2: A-record + FCrDNS ────────────────────────────────
    local host_file="${scan_dir}/hosts.tsv"
    local match_count=0 mismatch_count=0 noresolve_count=0

    if (( ptr_count > 0 )); then
        log_phase "Phase 2 — A-record + FCrDNS  [${THREADS} workers · ${TIMEOUT}s]"
        : > "$host_file"

        start_display "$ptr_count" "A-REC" "a"
        while IFS=$'\t' read -r ip hostname; do
            [[ -z "$ip" || -z "$hostname" ]] && continue
            sem_acquire
            (
                result=$(a_query "$ip" "$hostname")
                [[ -n "$result" ]] && printf '%s\n' "$result" >> "$host_file"
                printf 'A|%s\n' "$result" >&8   # done_n++ handled inside A| handler
                sem_release
            ) &
        done < "$ptr_file"
        exec 8>&-
        wait
        DISP_PID=""
        rm -f "${WDIR}/ctrl.fifo"

        match_count=$(    grep -c $'\tMATCH$'     "$host_file" 2>/dev/null) || match_count=0
        mismatch_count=$( grep -c $'\tMISMATCH$'  "$host_file" 2>/dev/null) || mismatch_count=0
        noresolve_count=$(grep -c $'\tNORESOLVE$' "$host_file" 2>/dev/null) || noresolve_count=0
        log_ok "FCrDNS:  ${G}✓ MATCH ${match_count}${N}  ${Y}⚠ MISMATCH ${mismatch_count}${N}  ${D}✗ NORESOLVE ${noresolve_count}${N}"
    else
        : > "$host_file"
        log_info "No PTR records — skipping A-record phase"
    fi

    # ── Domain extraction ─────────────────────────────────────────
    local dom_file="${scan_dir}/domains.txt"
    extract_domains "$ptr_file" > "$dom_file"
    local dom_count
    dom_count=$(( $(wc -l < "$dom_file" 2>/dev/null || echo 0) + 0 ))

    # ── Phase 3: AXFR (optional, -X flag) ─────────────────────────
    local axfr_vuln=0
    if (( AXFR_ENABLED && dom_count > 0 )); then
        log_phase "Phase 3 — AXFR Zone Transfer"
        log_warn "Target nameservers WILL log these requests"
        printf '\n'
        while read -r domain; do
            [[ -z "$domain" ]] && continue
            log_info "Testing: ${W}${domain}${N}"
            axfr_domain "$domain" "$scan_dir"
            axfr_vuln=$(( axfr_vuln + $? ))
        done < "$dom_file"
        printf '\n'
        if (( axfr_vuln > 0 )); then
            log_ok "${Y}AXFR VULNERABLE: ${axfr_vuln} domain(s) — check axfr_*.txt${N}"
        else
            log_ok "AXFR: all nameservers refused (good)"
        fi
    elif (( AXFR_ENABLED && dom_count == 0 )); then
        log_info "AXFR skipped — no domains discovered in Phase 1"
    fi

    # ── Summary file ──────────────────────────────────────────────
    local total_ips
    total_ips=$(( $(wc -l < "$ip_file" 2>/dev/null || echo 0) + 0 ))
    {
        printf 'WRAITH v%s\n' "$VERSION"
        printf '%.0s═' {1..40}; printf '\n'
        printf 'Range    : %s - %s\n' "$start_ip" "$end_ip"
        printf 'IPs      : %d\n'      "$total_ips"
        printf 'PTR      : %d\n'      "$ptr_count"
        printf 'MATCH    : %d\n'      "$match_count"
        printf 'MISMATCH : %d\n'      "$mismatch_count"
        printf 'NORESOLVE: %d\n'      "$noresolve_count"
        printf 'Domains  : %d\n'      "$dom_count"
        printf 'AXFR vuln: %d\n'      "$axfr_vuln"
        printf 'Resolver : %s\n'      "${RESOLVER:-system}"
        printf 'Threads  : %d\n'      "$THREADS"
        printf 'Timestamp: %s\n'      "$ts"
    } > "${scan_dir}/summary.txt"

    # ── Results table ─────────────────────────────────────────────
    print_results_table "$host_file"

    # ── Summary box ───────────────────────────────────────────────
    printf '\n'
    printf "  ${PRI}╔══════════════════════════════════════════╗${N}\n"
    printf "  ${PRI}║${N}  ${PRI}%-40s${N}  ${PRI}║${N}\n" "  ◈  WRAITH SCAN COMPLETE"
    printf "  ${PRI}╠══════════════════════════════════════════╣${N}\n"
    printf "  ${PRI}║${N}  ${D}%-24s${N}  ${W}%-13d${N}  ${PRI}║${N}\n" "IPs scanned"     "$total_ips"
    printf "  ${PRI}║${N}  ${D}%-24s${N}  ${W}%-13d${N}  ${PRI}║${N}\n" "PTR records"     "$ptr_count"
    printf "  ${PRI}║${N}  ${G}%-24s${N}  ${W}%-13d${N}  ${PRI}║${N}\n" "FCrDNS MATCH"    "$match_count"
    printf "  ${PRI}║${N}  ${Y}%-24s${N}  ${W}%-13d${N}  ${PRI}║${N}\n" "FCrDNS MISMATCH" "$mismatch_count"
    printf "  ${PRI}║${N}  ${D}%-24s${N}  ${W}%-13d${N}  ${PRI}║${N}\n" "NORESOLVE"       "$noresolve_count"
    printf "  ${PRI}║${N}  ${D}%-24s${N}  ${W}%-13d${N}  ${PRI}║${N}\n" "Unique domains"  "$dom_count"
    (( AXFR_ENABLED )) && \
    printf "  ${PRI}║${N}  ${Y}%-24s${N}  ${W}%-13d${N}  ${PRI}║${N}\n" "AXFR vulnerable" "$axfr_vuln"
    printf "  ${PRI}╚══════════════════════════════════════════╝${N}\n"

    print_files "$scan_dir"
    printf '\n'
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
