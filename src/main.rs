#![allow(unused)]

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::Write;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, LazyLock, LockResult, Mutex, TryLockResult};
use std::time::Duration;

#[cfg(feature = "pcap")]
use capture::PCAP_FILTER;
use chrono::Local;
use clap::Parser;
use futures::lock::Mutex as FuturesMutex;
use futures::{FutureExt, StreamExt, future, select};
use reliquary::network::command::GameCommandError;
use reliquary::network::command::command_id::{PlayerLoginFinishScRsp, PlayerLoginScRsp};
use reliquary::network::{ConnectionPacket, ConnectionPacketError, GamePacket, GameSniffer, KcpError, NetworkError};
use tokio::pin;
use tracing::instrument::WithSubscriber;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, instrument, warn};
use tracing_subscriber::filter::Filtered;
use tracing_subscriber::fmt::{MakeWriter, SubscriberBuilder};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer, Registry, reload};

#[cfg(feature = "stream")]
mod websocket;

use reliquary_archiver::export::Exporter;
use reliquary_archiver::export::database::Database;
use reliquary_archiver::export::fribbels::OptimizerExporter;

mod capture;
mod scopefns;
mod worker;

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg()]
    /// Path to output .json file to, per default: archive_output-%Y-%m-%dT%H-%M-%S.json
    output: Option<PathBuf>,

    /// Read packets from .pcap file instead of capturing live packets
    #[cfg(feature = "pcap")]
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// UDID to use when more than one iPhone is connected.
    #[cfg(all(target_os = "macos", feature = "pcap"))]
    #[arg(long)]
    udid: Option<String>,

    /// How long to wait in seconds until timeout is triggered for live captures
    #[arg(long, default_value_t = 120)]
    timeout: u64,

    /// Host a websocket server to stream relic/lc updates in real-time.
    /// This also disables the timeout
    #[cfg(feature = "stream")]
    #[arg(short, long)]
    stream: bool,

    /// Port to listen on for the websocket server, defaults to 23313
    #[cfg(feature = "stream")]
    #[arg(short = 'p', long, default_value_t = 23313)]
    websocket_port: u16,

    /// How verbose the output should be, can be set up to 3 times. Has no effect if RUST_LOG is set
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Path to output log to
    #[arg(short, long)]
    log_path: Option<PathBuf>,

    /// Don't wait for enter to be pressed after capturing
    #[arg(short, long)]
    exit_after_capture: bool,
}

#[derive(Debug, Clone)]
enum CaptureMode {
    Live,
    #[cfg(feature = "pcap")]
    Pcap(PathBuf),
}

impl CaptureMode {
    fn from_args(args: &Args) -> Self {
        #[cfg(feature = "pcap")]
        if let Some(path) = &args.pcap {
            return CaptureMode::Pcap(path.clone());
        }

        CaptureMode::Live
    }
}

#[tokio::main]
async fn main() {
    color_eyre::install().unwrap();

    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        old_hook(panic_info);
        error!("Backtrace: {:#?}", backtrace);
    }));

    let args = Args::parse();

    // Copy the exit_after_capture flag to a local variable before args is moved into the closure
    let exit_after_capture = args.exit_after_capture;

    tracing_init(&args);

    debug!(?args);

    // AssertUnwindSafe is justified as all we do is write a crash log before ending the program and therefore there is no risk posed by potential broken invariants
    if let Err(payload) = AssertUnwindSafe(capture(args)).catch_unwind().await {
        error!("the application panicked, this is a bug, please report it on GitHub or Discord");

        // Write crashlog
        if let Ok(mut file) = File::create("crashlog.txt") {
            if let TryLockResult::Ok(buffer) = LOG_BUFFER.try_lock() {
                let lines = buffer.join("\n");
                file.write_all(lines.as_bytes()).unwrap();
            } else {
                file.write_all("failed to lock log buffer".as_bytes()).unwrap();
            }
            file.write_all("\n\n".as_bytes()).unwrap();
            if let Some(s) = payload.downcast_ref::<&str>() {
                file.write_all(s.as_bytes()).unwrap();
            } else if let Some(s) = payload.downcast_ref::<String>() {
                file.write_all(s.as_bytes()).unwrap();
            } else {
                file.write_all("panic: unknown payload type".as_bytes()).unwrap();
            }
            info!("wrote crashlog to crashlog.txt");
        }

        info!("press enter to close");
        std::io::stdin().read_line(&mut String::new()).unwrap();
    }
}

async fn capture(args: Args) {
    let iphone_rvi = setup_iphone_capture(&args);
    let capture_interface = iphone_rvi.as_ref().map(|rvi| rvi.interface.clone());

    // Headless/CLI mode
    {
        log_capture_start_hints(&args);

        let database = Database::new();
        let sniffer = GameSniffer::new();
        let exporter = OptimizerExporter::new();

        let capture_mode = CaptureMode::from_args(&args);
        let export = match capture_mode {
            CaptureMode::Live => live_capture_wrapper(&args, exporter, sniffer, capture_interface).await,
            #[cfg(feature = "pcap")]
            CaptureMode::Pcap(path) => capture_from_pcap(exporter, sniffer, path),
        };

        if let Some(export) = export {
            let file_name = Local::now().format("archive_output-%Y-%m-%dT%H-%M-%S.json").to_string();
            let output_file = match args.output {
                Some(out) => out,
                _ => PathBuf::from(file_name.clone()),
            };

            info!("exporting collected data");
            match File::create(&output_file) {
                Ok(file) => {
                    if let Err(e) = serde_json::to_writer_pretty(&file, &export) {
                        error!("Failed to write to {}: {}", output_file.display(), e);
                    } else {
                        info!("wrote output to {}", output_file.canonicalize().unwrap().display());
                    }
                }
                Err(e) => {
                    error!("Failed to create file at {}: {}", output_file.display(), e);
                }
            }
        } else {
            warn!("skipped writing output");
        }
        if let Some(log_path) = args.log_path {
            info!("wrote logs to {}", log_path.display());
        }
    }
}

struct IphoneRviGuard {
    interface: String,
    #[cfg(all(target_os = "macos", feature = "pcap"))]
    udid: String,
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
impl Drop for IphoneRviGuard {
    fn drop(&mut self) {
        match Command::new(rvictl_path()).args(["-x", &self.udid]).output() {
            Ok(output) if output.status.success() => {
                info!(interface = %self.interface, "stopped iPhone Remote Virtual Interface");
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(interface = %self.interface, %stderr, "failed to stop iPhone Remote Virtual Interface");
            }
            Err(error) => {
                warn!(interface = %self.interface, %error, "failed to run rvictl cleanup");
            }
        }
    }
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn setup_iphone_capture(args: &Args) -> Option<IphoneRviGuard> {
    if args.pcap.is_some() {
        return None;
    }

    ensure_rvi_daemon_loaded();

    let udid = match &args.udid {
        Some(udid) => udid.clone(),
        None => match detect_connected_iphone_udid() {
            Ok(udid) => udid,
            Err(error) => {
                error!(%error, "could not auto-detect connected iPhone");
                error!("connect one iPhone over USB, trust this Mac, open Xcode once if needed, or pass --udid <UDID>");
                std::process::exit(2);
            }
        },
    };

    let output = match Command::new(rvictl_path()).args(["-s", &udid]).output() {
        Ok(output) => output,
        Err(error) => {
            error!(%error, "failed to run rvictl");
            error!("install Xcode and open it once so macOS installs rvictl, then retry");
            std::process::exit(2);
        }
    };

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(%stdout, %stderr, "rvictl failed to create an iPhone capture interface");
        std::process::exit(2);
    }

    let output_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let interface = match parse_rvictl_interface(&output_text) {
        Some(interface) => interface,
        None => {
            error!(%output_text, "rvictl succeeded but did not report a capture interface");
            std::process::exit(2);
        }
    };

    info!(%interface, "capturing iPhone traffic through Remote Virtual Interface");
    Some(IphoneRviGuard { interface, udid })
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn ensure_rvi_daemon_loaded() {
    const RPMUXD_PLIST: &str = "/Library/Apple/System/Library/LaunchDaemons/com.apple.rpmuxd.plist";

    if Command::new("launchctl")
        .args(["print", "system/com.apple.rpmuxd"])
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return;
    }

    if !std::path::Path::new(RPMUXD_PLIST).exists() {
        warn!("Apple RVI daemon plist was not found; rvictl may fail to start");
        return;
    }

    match Command::new("launchctl").args(["bootstrap", "system", RPMUXD_PLIST]).output() {
        Ok(output) if output.status.success() => {
            info!("loaded Apple RVI daemon");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(%stderr, "failed to load Apple RVI daemon; rvictl may fail to start");
        }
        Err(error) => {
            warn!(%error, "failed to run launchctl for Apple RVI daemon");
        }
    }
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn rvictl_path() -> &'static str {
    if std::path::Path::new("/Library/Apple/usr/bin/rvictl").exists() {
        "/Library/Apple/usr/bin/rvictl"
    } else {
        "rvictl"
    }
}

#[cfg(not(all(target_os = "macos", feature = "pcap")))]
fn setup_iphone_capture(_args: &Args) -> Option<IphoneRviGuard> {
    None
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn detect_connected_iphone_udid() -> Result<String, String> {
    match detect_connected_iphone_udid_with_devicectl() {
        Ok(udid) => return Ok(udid),
        Err(error) => {
            debug!(%error, "devicectl iPhone detection failed, falling back to xctrace");
        }
    }

    let output = Command::new("xcrun")
        .args(["xctrace", "list", "devices"])
        .output()
        .map_err(|error| format!("failed to run xcrun xctrace list devices: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "xcrun xctrace list devices failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut in_physical_devices = false;
    let mut udids = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed == "== Devices ==" {
            in_physical_devices = true;
            continue;
        }
        if trimmed.starts_with("== ") && trimmed != "== Devices ==" {
            in_physical_devices = false;
        }
        if !in_physical_devices || !trimmed.contains("iPhone") {
            continue;
        }
        if let Some(udid) = extract_last_parenthesized(trimmed).filter(|value| looks_like_udid(value)) {
            udids.push(udid.to_string());
        }
    }

    match udids.len() {
        0 => Err("no connected iPhone found in xctrace device list".to_string()),
        1 => Ok(udids.remove(0)),
        _ => Err(format!(
            "multiple connected iPhones found; pass --udid with one of: {}",
            udids.join(", ")
        )),
    }
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn detect_connected_iphone_udid_with_devicectl() -> Result<String, String> {
    let output = Command::new("xcrun")
        .args(["devicectl", "list", "devices"])
        .output()
        .map_err(|error| format!("failed to run xcrun devicectl list devices: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "xcrun devicectl list devices failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut identifiers = Vec::new();

    for line in stdout.lines() {
        if line.contains("iPhone") && line.contains("available") {
            let columns = line.split_whitespace().collect::<Vec<_>>();
            if let Some(identifier) = columns.iter().find(|column| looks_like_coredevice_identifier(column)) {
                identifiers.push((*identifier).to_string());
            }
        }
    }

    match identifiers.len() {
        0 => Err("no available iPhone found in devicectl device list".to_string()),
        1 => udid_for_coredevice_identifier(&identifiers[0]),
        _ => Err(format!(
            "multiple connected iPhones found; pass --udid with one of these CoreDevice identifiers: {}",
            identifiers.join(", ")
        )),
    }
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn udid_for_coredevice_identifier(identifier: &str) -> Result<String, String> {
    let output = Command::new("xcrun")
        .args(["devicectl", "device", "info", "details", "--device", identifier])
        .output()
        .map_err(|error| format!("failed to run xcrun devicectl device info details: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "xcrun devicectl device info details failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("• udid: ").map(str::to_string))
        .ok_or_else(|| format!("devicectl did not report a UDID for {identifier}"))
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn parse_rvictl_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (_, interface) = line.split_once("with interface ")?;
        interface.split_whitespace().next().map(str::to_string)
    })
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn extract_last_parenthesized(value: &str) -> Option<&str> {
    let end = value.rfind(')')?;
    let start = value[..end].rfind('(')?;
    Some(&value[start + 1..end])
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn looks_like_udid(value: &str) -> bool {
    value.len() >= 24 && value.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

#[cfg(all(target_os = "macos", feature = "pcap"))]
fn looks_like_coredevice_identifier(value: &str) -> bool {
    value.len() == 36 && value.chars().all(|c| c.is_ascii_hexdigit() || c == '-') && value.matches('-').count() == 4
}

fn log_capture_start_hints(args: &Args) {
    #[cfg(all(target_os = "macos", feature = "pcap"))]
    {
        if args.pcap.is_none() {
            info!("macOS live capture uses libpcap/BPF and may need sudo");
            info!("connect the iPhone over USB before tapping \"Click to Start\"");
        }
    }
}

struct VecWriter;

impl VecWriter {
    pub fn new() -> Self {
        Self
    }
}

pub static LOG_BUFFER: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));
pub static LOG_NOTIFY: LazyLock<tokio::sync::Notify> = LazyLock::new(tokio::sync::Notify::new);

type VecLayerHandle = Box<dyn Fn(LevelFilter) + Send>;
pub static VEC_LAYER_HANDLE: LazyLock<Mutex<Option<VecLayerHandle>>> = LazyLock::new(|| Mutex::new(None));

impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let str = String::from_utf8_lossy(buf);
        let lines = str.lines().map(|s| s.to_string());
        {
            let mut buffer = LOG_BUFFER.lock().unwrap();
            buffer.extend(lines);

            // Limit the buffer size to prevent unbounded memory growth, keeping only the most recent 100000 lines
            // (assuming an average of ~100 bytes per log line, this would use around 10MB of memory)
            if buffer.len() > 100000 {
                let range = 0..buffer.len() - 10000;
                buffer.drain(range);
            }
        }
        LOG_NOTIFY.notify_one();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct DualWriter<A: io::Write, B: io::Write> {
    m: Arc<Mutex<(A, B)>>,
}

impl<A: io::Write, B: io::Write> DualWriter<A, B> {
    fn new(a: A, b: B) -> Self {
        Self {
            m: Arc::new(Mutex::new((a, b))),
        }
    }
}

impl<A: io::Write, B: io::Write> io::Write for DualWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut m = self.m.lock().unwrap();
        m.0.write(buf)?;
        m.1.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut m = self.m.lock().unwrap();
        m.0.flush()?;
        m.1.flush()
    }
}

impl<'a, A: io::Write, B: io::Write> MakeWriter<'a> for DualWriter<A, B> {
    type Writer = DualWriter<A, B>;

    fn make_writer(&'a self) -> Self::Writer {
        DualWriter { m: self.m.clone() }
    }
}

fn tracing_init(args: &Args) {
    tracing_log::LogTracer::init().unwrap();

    fn env_filter(args: &Args) -> EnvFilter {
        EnvFilter::builder()
            .with_default_directive(
                match args.verbose {
                    0 => "reliquary_archiver=info",
                    1 => "info",
                    2 => "debug",
                    _ => "trace",
                }
                .parse()
                .unwrap(),
            )
            .from_env_lossy()
    }

    let (console_filter, handle) = reload::Layer::new(env_filter(args));
    let console_log = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(DualWriter::new(VecWriter::new(), io::stdout()))
        .with_filter(console_filter);

    *VEC_LAYER_HANDLE.lock().unwrap() = Some(Box::new(move |l| {
        handle.modify(|f| {
            *f = EnvFilter::builder()
                .parse(match l {
                    LevelFilter::TRACE => "trace",
                    LevelFilter::DEBUG => "debug",
                    LevelFilter::INFO => "info",
                    LevelFilter::WARN => "warn",
                    LevelFilter::ERROR => "error",
                    _ => "off",
                })
                .unwrap();
        });
    }));

    let file_log = if let Some(log_path) = &args.log_path {
        let log_file = File::create(log_path).unwrap();
        let file_log = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(Mutex::new(log_file))
            .with_filter(tracing::level_filters::LevelFilter::TRACE);
        Some(file_log)
    } else {
        None
    };

    let subscriber = Registry::default().with(console_log).with(file_log);

    tracing::subscriber::set_global_default(subscriber).expect("unable to set up logging");
}

// Helper function to process a packet and determine if capture should stop
enum ProcessResult {
    Continue,
    Stop,
}

// Simplified packet processing for file captures
fn file_process_packet<E>(exporter: &mut E, sniffer: &mut GameSniffer, payload: Vec<u8>) -> ProcessResult
where
    E: Exporter,
{
    if let Ok(packets) = sniffer.receive_packet(payload) {
        for packet in packets {
            if let GamePacket::Commands { conv_id, result } = packet {
                match result {
                    Ok(command) => {
                        exporter.read_command(command);

                        if exporter.is_initialized() {
                            info!("finished capturing");
                            return ProcessResult::Stop;
                        }
                    }
                    Err(e) => {
                        warn!(conv_id, %e);
                        if matches!(e, GameCommandError::VersionMismatch) {
                            // Client packet was misordered from server packet
                            // This will be reprocessed after we receive the new session key
                            return ProcessResult::Continue;
                        }

                        return ProcessResult::Stop;
                    }
                }
            }
        }
    }

    ProcessResult::Continue
}

#[instrument(skip_all)]
#[cfg(feature = "pcap")]
pub fn capture_from_pcap<E>(mut exporter: E, mut sniffer: GameSniffer, pcap_path: PathBuf) -> Option<E::Export>
where
    E: Exporter,
{
    info!("Capturing from pcap file: {}", pcap_path.display());
    let mut capture = pcap::Capture::from_file(&pcap_path).expect("could not read pcap file");
    capture.filter(PCAP_FILTER, false).unwrap();

    while let Ok(packet) = capture.next_packet() {
        match file_process_packet(&mut exporter, &mut sniffer, packet.data.to_vec()) {
            ProcessResult::Continue => {}
            ProcessResult::Stop => break,
        }
    }

    exporter.export()
}

async fn live_capture_wrapper<E>(args: &Args, exporter: E, sniffer: GameSniffer, capture_interface: Option<String>) -> Option<E::Export>
where
    E: Exporter,
    E::Export: From<<OptimizerExporter as Exporter>::Export>,
{
    use reliquary_archiver::export::database::get_database;
    #[cfg(feature = "stream")]
    use tokio::sync::watch;

    #[cfg(feature = "stream")]
    use crate::websocket::{PortSource, start_websocket_server};
    use crate::worker::MultiAccountManager;

    #[cfg(not(feature = "stream"))]
    let streaming = false;

    #[cfg(feature = "stream")]
    let streaming = args.stream;

    // Always use MultiAccountManager for consistency
    let database = get_database();
    let manager = Arc::new(FuturesMutex::new(MultiAccountManager::new()));

    #[cfg(feature = "stream")]
    let selected_account_tx = if streaming {
        let (tx, rx) = watch::channel::<Option<u32>>(None);

        // Start websocket server
        tokio::spawn(start_websocket_server(PortSource::Fixed(args.websocket_port), manager.clone(), rx));

        info!("WebSocket server starting on port {}...", args.websocket_port);
        Some(tx)
    } else {
        None
    };

    #[cfg(not(feature = "stream"))]
    let selected_account_tx = None;

    // Run live capture with manager
    let result = live_capture(args, manager, sniffer, selected_account_tx, streaming, capture_interface).await;
    result.map(|export| export.into())
}

#[instrument(skip_all)]
async fn live_capture(
    args: &Args,
    manager: Arc<FuturesMutex<worker::MultiAccountManager>>,
    mut sniffer: GameSniffer,
    selected_account_tx: Option<tokio::sync::watch::Sender<Option<u32>>>,
    streaming: bool,
    capture_interface: Option<String>,
) -> Option<<OptimizerExporter as Exporter>::Export> {
    use reliquary::network::command::command_id::{PlayerGetTokenScRsp, PlayerLoginFinishScRsp, PlayerLoginScRsp};
    use reliquary::network::command::proto::PlayerGetTokenScRsp::PlayerGetTokenScRsp as PlayerGetTokenScRspProto;

    let device_names = capture_interface.into_iter().collect();
    let rx = capture::listen_on_all(capture::pcap::FilteredPcapBackend::new(device_names));

    let packet_stream = rx.expect("Failed to start packet capture");
    let mut packet_stream = packet_stream.fuse();

    info!("instructions: go to main menu screen and go to the \"Click to Start\" screen");

    if streaming {
        info!("WebSocket streaming enabled - capture will run until manually stopped");
    }

    pin!(
        let timeout_future = maybe_timeout(
            if !streaming {
                info!("listening with a timeout of {} seconds...", args.timeout);
                Some(Duration::from_secs(args.timeout))
            } else {
                None
            }
        ).fuse();
    );

    let mut poisoned_sources = HashSet::new();
    let mut latest_uid: Option<u32> = None;

    'recv: loop {
        let received = select! {
            packet = packet_stream.next() => match packet {
                Some(packet) => packet,
                None => break 'recv,
            },

            _ = timeout_future => {
                break 'recv;
            }
        };

        match received {
            Ok(packet) => {
                if poisoned_sources.contains(&packet.source_id) {
                    // We already know that this source is poisoned, so we can skip it
                    continue;
                }

                match sniffer.receive_packet(packet.data) {
                    Ok(packets) => {
                        for packet in packets {
                            match packet {
                                GamePacket::Connection(c) => match c {
                                    ConnectionPacket::HandshakeEstablished { conv_id } => {
                                        info!(conv_id, "detected connection established");
                                    }
                                    ConnectionPacket::Disconnected => {
                                        info!("detected connection disconnected");
                                    }
                                    _ => {}
                                },
                                GamePacket::Commands { conv_id, result } => match result {
                                    Ok(command) => {
                                        if command.command_id == PlayerLoginScRsp {
                                            info!(conv_id, "detected login start");
                                        }

                                        // Check for UID discovery to register with manager
                                        if command.command_id == PlayerGetTokenScRsp {
                                            if let Ok(token_rsp) = command.parse_proto::<PlayerGetTokenScRspProto>() {
                                                let uid = token_rsp.uid;
                                                let mut mgr = manager.lock().await;
                                                mgr.register_uid(conv_id, uid);

                                                // Auto-select latest account
                                                latest_uid = Some(uid);
                                                if let Some(ref tx) = selected_account_tx {
                                                    tx.send(Some(uid)).ok();
                                                    info!(uid, "Auto-selected account for WebSocket streaming");
                                                }
                                            }
                                        }

                                        if !streaming && command.command_id == PlayerLoginFinishScRsp {
                                            info!("detected login end, assume initialization is finished");
                                            break 'recv;
                                        }

                                        // Route command to correct account exporter
                                        let exporter = {
                                            let mut mgr = manager.lock().await;
                                            mgr.get_or_create_exporter(conv_id)
                                        };
                                        exporter.lock().await.read_command(command);
                                    }
                                    Err(e) => {
                                        warn!(conv_id, %e);
                                        match e {
                                            GameCommandError::DecryptionKeyMissing => {
                                                // version is not supported, there's no point in capturing
                                                warn!(
                                                    "This game version is not supported yet. It usually takes a few days for Reliquary Archiver to get updated for new versions. Please try again at a later point."
                                                );
                                                break 'recv;
                                            }
                                            GameCommandError::HeaderTooShort { .. } | GameCommandError::CommandTooShort { .. } => {
                                                // structural parse errors, ignore
                                            }
                                            GameCommandError::VersionMismatch => {
                                                // Client packet was likely misordered from server packet
                                                // This will be reprocessed after we receive the new session key
                                            }
                                        }
                                    }
                                },
                            }
                        }

                        // Check if initialized for early exit in non-streaming mode
                        if !streaming {
                            if let Some(uid) = latest_uid {
                                let mgr = manager.lock().await;
                                if let Some(exporter) = mgr.get_account_exporter(uid) {
                                    if exporter.lock().await.is_initialized() {
                                        info!("retrieved all relevant packets, stop listening");
                                        break 'recv;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(%e);
                        match e {
                            NetworkError::ConnectionPacket(e) => {
                                if let ConnectionPacketError::TransportLayerNotPresent = e {
                                    continue;
                                }

                                // Connection errors are not fatal as all network interfaces are funneled through the same stream
                                // Just mark this source as poisoned and continue listening on other sources
                                poisoned_sources.insert(packet.source_id);
                                continue;
                            }
                            NetworkError::Kcp(e) => match e {
                                KcpError::HeaderTooShort { .. }
                                | KcpError::SegmentTooShort { .. }
                                | KcpError::ContentLengthExceedsData { .. }
                                | KcpError::InvalidSegmentHeader { .. } => {
                                    // structural parse errors, ignore
                                }
                                KcpError::ClientNotConstructed => {}
                                KcpError::PacketDoesNotBelongToConversation { .. } => {
                                    // reliquary should assign conversation ids correctly?
                                    // if it does happen, then something went wrong
                                    break 'recv;
                                }
                                KcpError::InnerKcpError(e) => break 'recv,
                            },
                            NetworkError::GameCommand(e) => match e {
                                GameCommandError::DecryptionKeyMissing => {
                                    // version is not supported, there's no point in capturing
                                    break 'recv;
                                }
                                GameCommandError::HeaderTooShort { .. } | GameCommandError::CommandTooShort { .. } => {
                                    // structural parse errors, ignore
                                }
                                GameCommandError::VersionMismatch => {
                                    // Client packet was likely misordered from server packet
                                    // This will be reprocessed after we receive the new session key
                                }
                            },
                        }
                    }
                }
            }
            Err(e) => {
                warn!(%e);
                break 'recv;
            }
        }
    }

    // Export from the latest account
    if let Some(uid) = latest_uid {
        let mgr = manager.lock().await;
        if let Some(exporter) = mgr.get_account_exporter(uid) {
            return exporter.lock().await.export();
        }
    }

    None
}

async fn maybe_timeout(timeout: Option<Duration>) -> () {
    if let Some(timeout) = timeout {
        tokio::time::sleep(timeout).await;
    } else {
        future::pending::<()>().await;
    }
}
