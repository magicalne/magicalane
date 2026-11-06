//! Server-side memory hygiene (issue #29).
//!
//! Root cause of the production RSS ratchet (see
//! `docs/plans/29-server-mem-growth.md`): under churn-heavy load the
//! server frees everything correctly (no reachable-growth leak), but
//! glibc strands freed chunks across per-thread arenas and below the
//! heap top, so RSS climbs monotonically — glibc NEVER returns free
//! memory to the OS on its own. On small instances the ratchet
//! eventually swap-thrashes the box (disk-read-IOPS-pinned incidents).
//!
//! Mitigation, applied to `Kind::Server` only:
//!   1. periodic `malloc_trim(0)` — walks every arena's free lists and
//!      releases top-of-heap pages back to the OS;
//!   2. optional `mallopt(M_ARENA_MAX, n)` cap — bounds arena
//!      proliferation on many-core hosts (each worker thread can grow
//!      its own arena). Off by default; enable via env if trim alone
//!      is insufficient on a given host.
//!
//! Knobs (read once at server startup):
//!   MAGICALANE_MEM_TRIM_SECS   trim interval; 0 disables (default 60)
//!   MAGICALANE_MALLOC_ARENA_MAX  cap arena count; 0/absent = untouched

use std::time::Duration;

/// Default interval between `malloc_trim` calls.
pub const DEFAULT_TRIM_SECS: u64 = 60;

/// glibc's `M_ARENA_MAX` mallopt parameter.
#[cfg(target_os = "linux")]
const M_ARENA_MAX: libc::c_int = -8;

/// Parse a non-negative seconds knob from the environment.
fn env_secs(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok())
}

/// Trim interval from `MAGICALANE_MEM_TRIM_SECS` (0 disables).
pub fn trim_interval(default: u64) -> Duration {
    Duration::from_secs(env_secs("MAGICALANE_MEM_TRIM_SECS").unwrap_or(default))
}

/// Whether the arena cap was requested and its value.
pub fn arena_max() -> Option<libc::c_int> {
    #[cfg(target_os = "linux")]
    {
        let v = std::env::var("MAGICALANE_MALLOC_ARENA_MAX")
            .ok()
            .and_then(|v| v.parse::<libc::c_int>().ok())?;
        (v > 0).then_some(v)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Start the trim loop (server kinds). No-op where unsupported or
/// disabled. Must be called from within the tokio runtime.
pub fn start_hygiene_loop() {
    let interval = trim_interval(DEFAULT_TRIM_SECS);
    if interval.is_zero() {
        log::debug!("mem: periodic trim disabled (MAGICALANE_MEM_TRIM_SECS=0)");
        return;
    }
    #[cfg(not(target_os = "linux"))]
    {
        // glibc-specific facility; other allocators (macOS, BSDs)
        // either trim eagerly or don't expose an equivalent.
        let _ = interval;
        log::debug!("mem: periodic trim not supported on this platform");
        return;
    }
    #[cfg(target_os = "linux")]
    {
        log::info!("mem: periodic malloc_trim every {interval:?}");
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let r = tokio::task::spawn_blocking(|| unsafe {
                    // 0 = release as much as possible at every arena top.
                    libc::malloc_trim(0)
                })
                .await;
                match r {
                    Ok(rc) if rc != 0 => {}
                    Ok(_) => log::trace!("mem: malloc_trim returned 0 (nothing to release)"),
                    Err(e) => log::debug!("mem: trim task failed: {e}"),
                }
            }
        });
    }
}

/// Apply the optional arena cap. Effective only if called before other
/// arenas exist (i.e. first thing in main). No-op where unsupported.
pub fn apply_arena_cap() {
    if let Some(n) = arena_max() {
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe { libc::mallopt(M_ARENA_MAX, n) };
            if rc == 0 {
                log::warn!("mem: mallopt(M_ARENA_MAX, {n}) failed");
            } else {
                log::info!("mem: glibc arena count capped at {n}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_interval_defaults_and_disables() {
        // No env set: default passes through.
        // (Env-var tests race across parallel test processes if they
        // mutate global state, so only assert the parse shape here.)
        assert_eq!(trim_interval(60), Duration::from_secs(60));
        assert_eq!(trim_interval(0), Duration::ZERO);
    }

    #[test]
    fn arena_max_absent_env_is_none() {
        // Requires the knob to be unset in the test environment — true in
        // CI and cargo test invocations (it is a server-deployment knob).
        if std::env::var_os("MAGICALANE_MALLOC_ARENA_MAX").is_some() {
            return; // knob set by outer environment; skip
        }
        assert_eq!(arena_max(), None);
    }
}
