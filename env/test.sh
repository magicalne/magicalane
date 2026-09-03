#!/usr/bin/env bash
# Legacy entry point - the testcase harness now lives in env/verify.sh.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify.sh" full "$@"
