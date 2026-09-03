# suites: tproxy-ws
# transports: quic kcp
# Workstation mode: a second client instance intercepts ALL tcp of the
# client container. Fetching origin AND the provably-private service with
# ZERO proxy configuration proves the whole path.
# NOTE: both fetches use IP addresses to avoid the DNS interceptor's
# circular dependency (first query triggers QUIC which needs DNS).
source "$TESTS_DIR/helpers.sh"
ws_start
ORIGIN_IP="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").IPAddress}}')"
out="$(exec_c curl -fsS --max-time 10 "http://$ORIGIN_IP/fixtures/hello.txt")" \
    || { ws_stop; fail "transparent fetch of origin failed"; }
assert_eq "$out" "$(fixture hello.txt)" "ws: transparent origin fetch (by IP) matches fixture"
TESTSVC_IP="$($CE inspect magicalane-testsvc --format '{{(index .NetworkSettings.Networks "magicalane-backend").IPAddress}}')"
id="$(exec_c curl -fsS --max-time 10 "http://$TESTSVC_IP:8080/id" | awk '{print $1}')" \
    || { ws_stop; fail "transparent fetch of private service failed"; }
svc_host="$(exec_s curl -fsS --max-time 3 "http://$TESTSVC_IP:8080/id" | awk '{print $1}')"
assert_eq "$id" "$svc_host" "ws: transparent fetch of PRIVATE service through tunnel"
ws_stop
