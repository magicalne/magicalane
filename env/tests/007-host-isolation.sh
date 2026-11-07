# suites: smoke
# transports: any
source "$TESTS_DIR/helpers.sh"
# The lab must not leak listeners onto the HOST. Scoped to processes
# from this repo's build tree: a dev workstation may legitimately run
# a production magicalane client on 1080/4433 — that is not a lab leak
# (issue #29 verification ran into exactly this).
lab_listener() { # port -> 0 if some listener's exe lives in this repo
    local port="$1" pid exe
    for pid in $(ss -ltnpH 2>/dev/null | grep -E ":${port} " | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
        case "$exe" in
            */magicalane-29/target/*) return 0 ;;
        esac
    done
    return 1
}
for port in 1080 4433; do
    if lab_listener "$port"; then
        fail "host has a lab-owned listener on $port"
    fi
done
pass "no lab-owned host listeners on proxy ports"
if curl -fsS --max-time 2 --socks5-hostname 127.0.0.1:1080 http://origin/ >/dev/null 2>&1; then
    # only meaningful when nothing legitimate owns 1080 on the host; a
    # production client would answer, which is expected on workstations
    if ! lab_listener 1080 && ! ss -ltnH 2>/dev/null | grep -qE ':1080 '; then
        fail "host could reach the client socks port"
    fi
fi
pass "host cannot reach client socks port (or a non-lab owner answered)"
