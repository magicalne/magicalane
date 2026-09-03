# suites: tproxy
# transports: any
source "$TESTS_DIR/helpers.sh"
if exec_a env | grep -qi proxy; then
    fail "app container must not have proxy env vars"
fi
out="$(exec_a curl -fsS --max-time 10 http://origin/fixtures/hello.txt)" \
    || fail "transparent fetch failed"
assert_eq "$out" "$(fixture hello.txt)" "transparent fetch matches fixture (zero proxy config)"
