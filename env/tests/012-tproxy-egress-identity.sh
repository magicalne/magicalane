# suites: tproxy
# transports: any
source "$TESTS_DIR/helpers.sh"
fetched="$(exec_a curl -fsS --max-time 10 http://origin/fixtures/hostname)" \
    || fail "transparent hostname fetch failed"
origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
assert_eq "$fetched" "$origin_host" "transparently fetched page really served by origin"
