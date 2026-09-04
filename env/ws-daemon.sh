#!/bin/sh
# ws-daemon.sh: reliably start/stop the workstation-mode magicalane client
# inside the client container. Written by up.sh into /usr/local/bin/.
# The PID file makes ws_stop exact; setsid+redirect detaches properly
# from any podman exec session lifecycle.
PIDFILE=/tmp/ws-client.pid
LOGFILE=/tmp/ws.log

alive() {
    [ -f "$PIDFILE" ] || return 1
    pid=$(cat "$PIDFILE" 2>/dev/null) || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    # zombies pass kill -0 but are dead (PID 1 in containers may not reap)
    ! grep -q 'State:.*Z' "/proc/$pid/status" 2>/dev/null
}

start() {
    CFG="${1:-/etc/magicalane/client-ws.toml}"
    if alive; then
        exit 0  # already running
    fi
    rm -f "$PIDFILE"
    setsid magicalane --config "$CFG" \
        </dev/null >"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
}

stop() {
    if [ -f "$PIDFILE" ]; then
        pid="$(cat $PIDFILE)"
        kill "$pid" 2>/dev/null
        # TERM triggers iptables teardown, which can stall on nft lock
        # contention under rapid restart cycles; ensure actual death.
        for _ in 1 2 3 4 5 6; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        kill -9 "$pid" 2>/dev/null
        rm -f "$PIDFILE"
    fi
    # fallback: kill by pattern (same death guarantee)
    pkill -f "client-ws.*toml" 2>/dev/null
    sleep 0.3
    pkill -9 -f "client-ws.*toml" 2>/dev/null
}

SCRIPT_CMD="${1:-start}"
SCRIPT_CFG="${2:-}"
case "$SCRIPT_CMD" in
    start) start "$SCRIPT_CFG" ;;
    stop) stop ;;
    status)
        if alive; then
            echo "running"
        else
            echo "stopped"
        fi
        ;;
esac
