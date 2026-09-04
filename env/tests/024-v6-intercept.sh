# suites: fakeip v6
# transports: quic
# v6 interception (CP3): a connection to origin's LITERAL v6 address
# must be caught by the MGL6 mirror and routed through the tunnel —
# origin's access log must NOT show the client's v6 address (no leak).
# Requires the dual-stack env (verify.sh deploys it for the v6 suite).
source "$TESTS_DIR/helpers.sh"
FAKEIP_CFG="/etc/magicalane/client-ws-fakeip.toml"

ORIGIN_V6="$($CE inspect magicalane-origin --format '{{(index .NetworkSettings.Networks "magicalane-net").GlobalIPv6Address}}')"
[ -n "$ORIGIN_V6" ] || fail "origin has no v6 address (env not dual-stack?)"

ws_start_cfg "$FAKEIP_CFG"
body="$(exec_c curl -fsS --max-time 10 "http://[$ORIGIN_V6]/fixtures/hostname")" \
    || { ws_stop; fail "v6: literal fetch failed"; }
ws_stop

origin_host="$($CE exec magicalane-origin cat /etc/hostname)"
assert_eq "$body" "$origin_host" "v6: literal fetch served by origin (through tunnel)"

# No leak: the access-log peer must not be the client's v6.
CLIENT_V6="$($CE inspect magicalane-client --format '{{(index .NetworkSettings.Networks "magicalane-net").GlobalIPv6Address}}')"
[ -n "$CLIENT_V6" ] || fail "client has no v6 address"
peer="$($CE logs --since 1m magicalane-origin 2>&1 | grep 'GET /fixtures/hostname' | tail -1 | grep -oE '^[0-9a-fA-F:]*[0-9a-fA-F]' | head -1)"
# python http.server logs v6 peers as "::ffff:..." or plain v6; the
# client v6 is fd00:89::x — a direct leak would show exactly it.
case "$($CE logs --since 1m magicalane-origin 2>&1 | grep 'GET /fixtures/hostname' | tail -1)" in
    *"$CLIENT_V6"*) fail "v6 LEAK: origin saw the client's literal v6 ($CLIENT_V6)" ;;
    *) echo "    v6: no client-v6 peer in origin log (intercepted)" ;;
esac
