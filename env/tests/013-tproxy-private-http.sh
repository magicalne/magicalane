# suites: tproxy
# transports: any
# The strongest transparent assertion: the app is on NO network that can
# reach the private service. Success proves interception + tunnel + server
# egress all worked.
source "$TESTS_DIR/helpers.sh"
id="$(exec_a curl -fsS --max-time 10 http://testsvc:8080/id | awk '{print $1}')" \
    || fail "transparent fetch of private service failed"
svc_host="$(exec_s curl -fsS --max-time 3 http://testsvc:8080/id | awk '{print $1}')"
assert_eq "$id" "$svc_host" "app reached private service transparently through the tunnel"
