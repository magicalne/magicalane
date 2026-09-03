# suites: transport
# transports: quic kcp
source "$TESTS_DIR/helpers.sh"
exec_c magabench run --socks 127.0.0.1:1080 --target testsvc:9001 \
    --pings 5 --connects 2 --conc-conns 2 --conc-pings 3 \
    --dl-bytes 262144 --ul-bytes 131072 --dl-par 1 >/dev/null \
    || fail "framed TCP echo through tunnel failed"
pass "framed TCP echo to private service through tunnel"
