// SPDX-License-Identifier: MIT OR Apache-2.0

// CI runs `cargo clippy --all-targets` with `-D clippy::unwrap_used
// -D clippy::expect_used -D clippy::panic -D clippy::as_conversions`. These
// restriction lints are useful in production paths but are routine in test
// code (setup/assert/teardown) where panic-on-failure is the expected
// behaviour. Allow them in the test build only.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::as_conversions
    )
)]

//! Library entry point for the vhost-user-wireguard daemon.
//!
//! [`run`] is the top-level orchestration that loads the configuration,
//! constructs every subsystem ([`wg::WgEngine`], [`dhcp::DhcpServer`],
//! [`datapath::WgNetBackend`]), drops privileges, signals readiness to
//! systemd, and finally runs the vhost-user serve loop until a SIGTERM/SIGINT
//! is received or the frontend disconnects.

pub mod arp;
pub mod config;
pub mod datapath;
pub mod dhcp;
pub mod error;
pub mod ops;
pub mod wg;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use zeroize::Zeroize;

use crate::config::cli::CliArgs;
use crate::datapath::WgNetBackend;
use crate::datapath::intercept::InterceptCfg;
use crate::dhcp::DhcpServer;
use crate::error::{ConfigError, Error, VhostError, WgError};
use crate::ops::logging::LogFormat;
use crate::wg::WgEngine;

/// Default lease file path when none is configured.
///
/// `/var/lib` is the FHS-mandated location for daemon state that must survive
/// reboots (DHCP leases included).
const DEFAULT_LEASE_PATH: &str = "/var/lib/vhost-user-wireguard/leases.json";

/// Locally-administered MAC address advertised as the synthetic gateway.
///
/// The first byte (`0x02`) is the locally-administered, unicast pattern.
/// This MAC is opaque to the guest — it appears as the gateway's link-layer
/// identity in ARP replies and DHCP option 6 — and is intentionally fixed so
/// that lease persistence and the trust-boundary classifier stay deterministic
/// across daemon restarts.
const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Daemon name advertised to the vhost-user framework.
const DAEMON_NAME: &str = "vhost-user-wireguard";

/// Run the daemon to completion.
///
/// This is the single entrypoint exposed to `main.rs`; it consumes the parsed
/// CLI arguments, fully wires up every subsystem, runs the vhost-user serve
/// loop, and returns once a shutdown signal is observed (or the loop exits
/// for an unrelated reason).
///
/// The function is sequenced as follows:
///
/// 1. Load TOML configuration from disk.
/// 2. Apply CLI overrides on top of the loaded config.
/// 3. Honor `--check-config`: validate, print "config OK", and return early.
/// 4. Validate the merged config (collects every issue in one pass).
/// 5. Install the global tracing subscriber.
/// 6. Materialise the WireGuard private key (file or inline base64).
/// 7. Build the WG engine; preshared keys are loaded inside it.
/// 8. Best-effort zeroize the inline key strings still living in [`Config`].
/// 9. Construct the DHCP server, lease file is loaded internally.
/// 10. Build the trust-boundary [`InterceptCfg`].
/// 11. Build the [`WgNetBackend`] and wrap it in [`Arc<Mutex<_>>`].
/// 12. Spawn a signal-handling thread that pokes the backend's exit fd.
/// 13. Drop privileges, then drop capabilities (in that order).
/// 14. Tell systemd we are ready (`READY=1`).
/// 15. Build the [`VhostUserDaemon`] and run the serve loop.
/// 16. On loop exit: notify systemd of stopping, signal the handler thread to
///     exit by raising the same exit fd, join it, and return the loop result.
pub fn run(cli: CliArgs) -> Result<(), Error> {
    // 1. Resolve the config path. CliArgs uses Option<PathBuf>; if absent we
    //    cannot proceed because the daemon's behaviour is config-driven.
    let config_path = cli.config.clone().ok_or_else(|| {
        Error::Config(ConfigError::FileRead {
            path: PathBuf::new(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing --config <path>",
            ),
        })
    })?;
    let config = crate::config::toml::load(&config_path)?;

    // 2. Merge CLI overrides into the loaded config.
    let mut config = crate::config::cli::apply_overrides(config, &cli);

    // 3. --check-config: validate, print, exit early. We deliberately do NOT
    //    install the tracing subscriber here — the user wants a single-line
    //    success/failure on stdout, not structured logs interleaving.
    if cli.check_config {
        crate::config::validate::validate(&config)?;
        #[allow(clippy::print_stdout)]
        // User-facing CLI output for --check-config; intentional stdout write
        {
            println!("config OK");
        }
        return Ok(());
    }

    // 4. Full validation. Returns Err with every collected issue at once.
    crate::config::validate::validate(&config)?;

    // 5. Install the global tracing subscriber. AlreadyInstalled is treated
    //    as a hard error here because the daemon binary owns the subscriber.
    let log_format = match cli.log_format.as_deref().unwrap_or("text") {
        "json" => LogFormat::Json,
        _ => LogFormat::Text,
    };
    let log_filter = cli.log_filter.as_deref().unwrap_or("info");
    crate::ops::logging::init(log_format, log_filter)?;

    // 6. Load the private key. Validation already enforced that exactly one
    //    of (private_key_file, private_key) is set, but we re-check here so
    //    that a future skip-validate path can't silently load nothing.
    let private_key = match (
        config.wireguard.private_key_file.as_ref(),
        config.wireguard.private_key.as_ref(),
    ) {
        (Some(path), None) => crate::wg::keys::load_private_key(path)?,
        (None, Some(s)) => crate::wg::keys::parse_private_key_base64(s)?,
        (Some(_), Some(_)) => return Err(Error::Wg(WgError::AmbiguousKeySource)),
        (None, None) => return Err(Error::Wg(WgError::NoKeySource)),
    };

    // 7. Build the WG engine. WgEngine::new also loads each peer's preshared
    //    key (file or inline base64) into the per-peer Tunn state.
    let wg = WgEngine::new(&config.wireguard, &private_key)?;

    // 8. Best-effort zeroize the inline key strings still resident in the
    //    Config struct. The String contents are overwritten in place; the
    //    backing allocation is later dropped when `config` goes out of scope.
    if let Some(ref mut s) = config.wireguard.private_key {
        s.zeroize();
    }
    for peer in config.wireguard.peers.iter_mut() {
        if let Some(ref mut s) = peer.preshared_key {
            s.zeroize();
        }
    }

    // 9. Build the DHCP server. LeaseFile::load() runs inside DhcpServer::new
    //    via LeaseFile::new(...).load() — corrupt files are renamed and the
    //    server starts from an empty lease table.
    //
    //    The path defaults to `/var/lib/vhost-user-wireguard/leases.json`
    //    (FHS), but can be overridden via the `VUWG_LEASE_PATH` environment
    //    variable. The override exists so the integration test harness can
    //    redirect persistence to a test-owned tempdir without requiring root.
    let lease_path = std::env::var_os("VUWG_LEASE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LEASE_PATH));
    let dhcp = DhcpServer::new(
        config.network.clone(),
        config.dhcp.clone(),
        GATEWAY_MAC,
        config.vm.clone(),
        lease_path,
    )?;

    // 10. Trust-boundary configuration consumed by the TX classifier.
    let intercept_cfg = InterceptCfg {
        vm_mac: config.vm.mac.bytes(),
        vm_mtu: config.vm.mtu,
        gateway_ip: config.network.gateway,
        gateway_mac: GATEWAY_MAC,
    };

    // 11. Wire the backend. WgNetBackend::new also creates the externally-
    //     driven shutdown EventFd that the signal handler will poke.
    let checkpoint_interval = Duration::from_secs(config.dhcp.checkpoint_secs);
    let backend = WgNetBackend::new(
        intercept_cfg,
        dhcp,
        wg,
        config.vm.ip,
        config.vhost_user.queue_size,
        checkpoint_interval,
        config.busy_poll.clone(),
    )?;
    let backend = Arc::new(Mutex::new(backend));

    // 12. Spawn the signal-handling thread. signal_hook installs the actual
    //     POSIX signal handlers and we just iterate over the produced events.
    let signal_thread = spawn_signal_thread(Arc::clone(&backend))?;

    // 13. Drop privileges (setgid before setuid) and then capabilities.
    //     These steps must happen BEFORE notify_ready: systemd interprets
    //     READY=1 as "the daemon has reached its fully-initialised state",
    //     and we don't want privileged code paths to run after that point.
    //     CliArgs in this build does not yet expose user/group flags; pass
    //     None so privilege-drop is a structured no-op when not configured.
    crate::ops::caps::drop_privileges(None, None)?;
    crate::ops::caps::drop_capabilities()?;

    // 14. Tell systemd we are ready. notify_ready() is best-effort: it
    //     returns Ok(()) even if NOTIFY_SOCKET is unset (i.e. when running
    //     outside of systemd), so this is safe in foreground mode too.
    crate::ops::systemd::notify_ready()?;

    // 15. Build the daemon and run the serve loop. Memory is empty at first;
    //     the frontend populates it via SET_MEM_TABLE during negotiation.
    let mem = GuestMemoryAtomic::new(GuestMemoryMmap::<()>::new());
    let socket_path = config.vhost_user.socket.clone();
    let daemon = VhostUserDaemon::new(DAEMON_NAME.to_string(), Arc::clone(&backend), mem)
        .map_err(|e| Error::Vhost(VhostError::Backend(e.to_string())))?;

    let serve_result = crate::datapath::run_serve_loop(daemon, Arc::clone(&backend), &socket_path);

    // 16. Tear down. notify_stopping is best-effort and swallows errors
    //     internally, so we propagate it without checking. Then poke the
    //     exit fd to wake the signal thread (in case the loop exited for a
    //     reason other than signal delivery), and join it.
    let _ = crate::ops::systemd::notify_stopping();

    if let Ok(b) = backend.lock() {
        let _ = b.signal_exit();
    }

    if let Err(panic) = signal_thread.join() {
        tracing::warn!(?panic, "signal_thread_panicked");
    }

    serve_result
}

/// Spawn a thread that converts SIGTERM/SIGINT into a write to the backend's
/// shutdown [`vmm_sys_util::eventfd::EventFd`].
///
/// The thread exits after a single signal — there is no point looping because
/// the serve loop will tear down on the first observed shutdown event.
fn spawn_signal_thread(backend: Arc<Mutex<WgNetBackend>>) -> Result<thread::JoinHandle<()>, Error> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGTERM, SIGINT])?;

    let handle = thread::Builder::new()
        .name("signal-handler".to_string())
        .spawn(move || {
            if let Some(signal) = signals.forever().next() {
                tracing::info!(signal, "received_shutdown_signal");
                match backend.lock() {
                    Ok(b) => {
                        if let Err(e) = b.signal_exit() {
                            tracing::warn!(error = %e, "signal_exit_failed");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "backend_mutex_poisoned_in_signal_thread");
                    }
                }
            }
        })?;

    Ok(handle)
}
