# suites: smoke transport
# transports: quic kcp
# The test service is ONLY reachable through the tunnel: success here
# proves the full client -> transport -> server -> backend path.
source "$TESTS_DIR/helpers.sh"
id="$(curl_socks http://testsvc:8080/id | awk '{print $1}')" || fail "private service fetch via socks failed"
svc_host="$(exec_s curl -fsS --max-time 3 http://testsvc:8080/id | awk '{print $1}')"
assert_eq "$id" "$svc_host" "private HTTP service reached through the tunnel"
