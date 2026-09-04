#!/bin/sh
# ws-daemon.sh: reliably start/stop the workstation-mode magicalane client
# inside the client container. Written by up.sh into /usr/local/bin/.
# The PID file makes ws_stop exact; setsid+redirect detaches properly
# from any podman exec session lifecycle.
PIDFILE=/tmp/ws-client.pid
LOGFILE=/tmp/ws.log

start() {
    CFG="${1:-/etc/magicalane/client-ws.toml}"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        exit 0  # already running
    fi
    setsid magicalane --config "$CFG" \
        </dev/null >"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
}

stop() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat $PIDFILE)" 2>/dev/null
        rm -f "$PIDFILE"
    fi
    # fallback: kill by pattern
    pkill -f "client-ws.*toml" 2>/dev/null
}

SCRIPT_CMD="${1:-start}"
SCRIPT_CFG="${2:-}"
case "$SCRIPT_CMD" in
    start) start "$SCRIPT_CFG" ;;
    stop) stop ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
            echo "running"
        else
            echo "stopped"
        fi
        ;;
esac
