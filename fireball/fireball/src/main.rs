use std::iter::once;
use axum::response::Html;
use http::header::HeaderName;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use anyhow::{Context, anyhow};
use aya::maps::HashMap;
use aya::Bpf;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;
use aya::{
    include_bytes_aligned,
    maps::MapData,
    programs::{Xdp, XdpFlags},
};
use aya_log::BpfLogger;
use axum::{
    extract::Path,
    routing::{get, post},
    Extension, Json, Router,
};
use http::header::AUTHORIZATION;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultMakeSpan, TraceLayer},
    validate_request::ValidateRequestHeaderLayer,
};
use figment::{Figment, providers::{Yaml, Format}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap as StdHashMap;
use rusqlite::{Connection, Result};
use std::collections::VecDeque;

mod db;
use db::*;

// Command-line arguments
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens33")]
    iface: String,

    #[clap(short, long, value_delimiter = ' ', num_args = 1..)]
    block_ip: Vec<String>,

    #[clap(short = 'p', long, value_delimiter = ' ', num_args = 1..)]
    block_proto: Vec<String>,
}

// Axum states
#[derive(Clone)]
pub struct AppState {
    blocklist_map_state: BlocklistMapState,
    protocol_map: Arc<StdHashMap<&'static str, u64>>,
    db_conn: Arc<Mutex<Connection>>,
}

#[derive(Clone)]
pub struct BlocklistMapState {
    pub srcip_filter: Arc<Mutex<HashMap<MapData, u32, u8>>>,
    pub blocked_protocols: Arc<Mutex<HashMap<MapData, u64, u8>>>,
    pub dropped_ip_counts: Arc<Mutex<HashMap<MapData, u32, u64>>>,
    pub dropped_protocol_counts: Arc<Mutex<HashMap<MapData, u64, u64>>>,
}

#[derive(Deserialize)]
struct BlockIpRequest {
    ip: String,
}

#[derive(Deserialize)]
struct BlockProtoRequest {
    protocol: String,
}

#[derive(Serialize)]
struct Response {
    status: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse(); 
    let config: StdHashMap<String, String> = Figment::new()
        .merge(Yaml::file("config.yaml"))
        .extract()?;

    env_logger::init();

    let db_conn = Connection::open("firewall.db").context("Failed to connect to database")?;
    db::initialize_db(&db_conn).context("Failed to initialize database")?;

    let protocol_map: Arc<StdHashMap<&'static str, u64>> = Arc::new([
        ("icmp", 1),
        ("tcp", 6),
        ("udp", 17),
        ("ftp", 21),
        ("ssh", 22),
        ("smtp",25),
        ("dns", 53),
        ("http", 80),
        ("kerberos", 88),
        ("https", 443),
        ("vmware server", 902),
        ("rdp", 3389),
    ].iter().cloned().collect());

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/fireball"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/fireball"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBpf logger: {}", e);
    }

    // Create the maps
    let srcip_filter_map = {
        let map = bpf.take_map("BLOCKED_IPS").context("Failed to get BLOCKED_IPS map")?;
        HashMap::<_, u32, u8>::try_from(map)?
    };
    let blocked_protocols_map = {
        let map = bpf.take_map("BLOCKED_PROTOCOLS").context("Failed to get BLOCKED_PROTOCOLS map")?;
        HashMap::<_, u64, u8>::try_from(map)?
    };

    let dropped_ip_counts_map = {
        let map = bpf.take_map("DROPPED_IP_COUNTS").context("Failed to get DROPPED_IP_COUNTS map")?;
        HashMap::<_, u32, u64>::try_from(map)?
    };
    let dropped_protocol_counts_map = {
        let map = bpf.take_map("DROPPED_PROTOCOL_COUNTS").context("Failed to get DROPPED_PROTOCOL_COUNTS map")?;
        HashMap::<_, u64, u64>::try_from(map)?
    };

    // Wrap the maps in Arc<Mutex<_>>
    let srcip_filter = Arc::new(Mutex::new(srcip_filter_map));
    let blocked_protocols = Arc::new(Mutex::new(blocked_protocols_map));
    let dropped_ip_counts = Arc::new(Mutex::new(dropped_ip_counts_map));
    let dropped_protocol_counts = Arc::new(Mutex::new(dropped_protocol_counts_map));

    // Load blocked IPs from the database
    let blocked_ips = db::get_blocked_ips(&db_conn)?;
    for ip in blocked_ips {
        let addr: Ipv4Addr = Ipv4Addr::from_str(&ip).context("Failed to parse IP address")?;
        let mut filter = srcip_filter.lock().unwrap();
        filter.insert(u32::from(addr), 1, 0).context("Failed to insert into BLOCKED_IPS")?;
    }

    // Load blocked protocols from the database
    let blocked_protos = db::get_blocked_protocols(&db_conn)?;
    for proto in blocked_protos {
        let mut protocols = blocked_protocols.lock().unwrap();
        protocols.insert(proto, 1, 0).context("Failed to insert into BLOCKED_PROTOCOLS")?;
    }

    // Attach the XDP program
    {
        let program: &mut Xdp = bpf.program_mut("fireball").context("Failed to find fireball program")?.try_into()?;
        program.load()?;
        program.attach(&opt.iface, XdpFlags::SKB_MODE)
            .context("Failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    }

    let state = AppState {
        blocklist_map_state: BlocklistMapState {
            srcip_filter: srcip_filter.clone(),
            blocked_protocols: blocked_protocols.clone(),
            dropped_ip_counts: dropped_ip_counts.clone(),
            dropped_protocol_counts: dropped_protocol_counts.clone(),
        },
        protocol_map: protocol_map.clone(),
        db_conn: Arc::new(Mutex::new(db_conn)),
    };

    let app = Router::new()
        .route("/block_ip", post(block_ip_handler))
        .route("/unblock_ip", post(unblock_ip_handler))
        .route("/block_proto", post(block_proto_handler))
        .route("/unblock_proto", post(unblock_proto_handler))
        .route("/protocols", get(get_protocols_handler))
        .route("/health", get(health_check))
        .route("/blocked_ips", get(get_blocked_ips_handler))
        .route("/blocked_protocols", get(get_blocked_protocols_handler))
        .route("/charts", get(charts_handler))
        .route("/dropped_stats", get(get_dropped_stats_handler))
        .route("/", get(|| async { Html(std::include_str!("../../static/index.html")) }))
        .layer(Extension(state));
         ServiceBuilder::new()
                .layer(CorsLayer::new().allow_origin(Any))
                /* .layer(ValidateRequestHeaderLayer::custom(|value: &str| {
                    if value == "APITOKEN" {
                        Ok(())
                    } else {
                        Err(anyhow!("INVALID API"))
                    }
                }))*/
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(DefaultMakeSpan::new().include_headers(true)),
                )
                .layer(SetSensitiveRequestHeadersLayer::new(once(AUTHORIZATION)));
        

    let server = axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service());

    info!("Axum server running on http://0.0.0.0:8080");

    tokio::select! {
        _ = server => {},
        _ = signal::ctrl_c() => {},
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

async fn health_check() -> &'static str {
    "Server is running"
}

async fn block_ip_handler(
    Json(payload): Json<BlockIpRequest>,
    Extension(state): Extension<AppState>,
) -> Json<Response> {
    let addr: Ipv4Addr = match Ipv4Addr::from_str(&payload.ip) {
        Ok(addr) => addr,
        Err(_) => return Json(Response { status: "Invalid IP address".to_string() }),
    };

    let mut filter = state.blocklist_map_state.srcip_filter.lock().unwrap();
    filter.insert(u32::from(addr), 1, 0).unwrap();

    let conn = state.db_conn.lock().unwrap();
    db::add_blocked_ip(&conn, &payload.ip).unwrap();

    // Log current blocked IPs
    let blocked_ips: Vec<String> = filter.iter().filter_map(|entry| entry.ok().map(|(key, _value)| Ipv4Addr::from(key).to_string())).collect();
    info!("Blocked IPs: {:?}", blocked_ips);

    Json(Response { status: "IP blocked".to_string() })
}

async fn unblock_ip_handler(
    Json(payload): Json<BlockIpRequest>,
    Extension(state): Extension<AppState>,
) -> Json<Response> {
    let addr: Ipv4Addr = match Ipv4Addr::from_str(&payload.ip) {
        Ok(addr) => addr,
        Err(_) => return Json(Response { status: "Invalid IP address".to_string() }),
    };

    let mut filter = state.blocklist_map_state.srcip_filter.lock().unwrap();
    filter.remove(&u32::from(addr)).unwrap();

    let conn = state.db_conn.lock().unwrap();
    db::remove_blocked_ip(&conn, &payload.ip).unwrap();

    // Log current blocked IPs
    let blocked_ips: Vec<String> = filter.iter().filter_map(|entry| entry.ok().map(|(key, _value)| Ipv4Addr::from(key).to_string())).collect();
    info!("Blocked IPs: {:?}", blocked_ips);

    Json(Response { status: "IP unblocked".to_string() })
}

async fn block_proto_handler(
    Json(payload): Json<BlockProtoRequest>,
    Extension(state): Extension<AppState>,
) -> Json<Response> {
    info!("Received request to block protocol: {}", payload.protocol);
    let proto_str_lower = payload.protocol.to_lowercase();
    if let Some(&proto_num) = state.protocol_map.get(proto_str_lower.as_str()) {
        let mut protocols = state.blocklist_map_state.blocked_protocols.lock().unwrap();
        protocols.insert(proto_num, 1, 0).unwrap();

        let conn = state.db_conn.lock().unwrap();
        db::add_blocked_protocol(&conn, proto_num).unwrap();

        // Log current blocked protocols
        let blocked_protocols: Vec<String> = protocols.iter().filter_map(|entry| entry.ok().map(|(key, _value)| {
            state.protocol_map.iter().find_map(|(&k, &v)| if v == key { Some(k.to_string()) } else { None }).unwrap_or_else(|| format!("Unknown ({})", key))
        })).collect();
        info!("Blocked protocols: {:?}", blocked_protocols);

        Json(Response { status: "Protocol blocked".to_string() })
    } else {
        warn!("Unknown protocol: {}", payload.protocol);
        Json(Response { status: "Unknown protocol".to_string() })
    }
}

async fn unblock_proto_handler(
    Json(payload): Json<BlockProtoRequest>,
    Extension(state): Extension<AppState>,
) -> Json<Response> {
    info!("Received request to unblock protocol: {}", payload.protocol);
    let proto_str_lower = payload.protocol.to_lowercase();
    if let Some(&proto_num) = state.protocol_map.get(proto_str_lower.as_str()) {
        let mut protocols = state.blocklist_map_state.blocked_protocols.lock().unwrap();
        protocols.remove(&proto_num).unwrap();

        let conn = state.db_conn.lock().unwrap();
        db::remove_blocked_protocol(&conn, proto_num).unwrap();

        // Log current blocked protocols
        let blocked_protocols: Vec<String> = protocols.iter().filter_map(|entry| entry.ok().map(|(key, _value)| {
            state.protocol_map.iter().find_map(|(&k, &v)| if v == key { Some(k.to_string()) } else { None }).unwrap_or_else(|| format!("Unknown ({})", key))
        })).collect();
        info!("Blocked protocols: {:?}", blocked_protocols);

        Json(Response { status: "Protocol unblocked".to_string() })
    } else {
        warn!("Unknown protocol: {}", payload.protocol);
        Json(Response { status: "Unknown protocol".to_string() })
    }
}

async fn get_blocked_ips_handler(
    Extension(state): Extension<AppState>,
) -> Json<Vec<String>> {
    let conn = state.db_conn.lock().unwrap();
    match get_blocked_ips(&conn) {
        Ok(ips) => {
            info!("Loaded blocked IPs from database: {:?}", ips);
            Json(ips)
        },
        Err(e) => {
            warn!("Failed to load blocked IPs from database: {}", e);
            Json(vec![])
        }
    }
}

async fn get_blocked_protocols_handler(
    Extension(state): Extension<AppState>,
) -> Json<Vec<String>> {
    let conn = state.db_conn.lock().unwrap();
    match get_blocked_protocols(&conn) {
        Ok(protocols) => {
            let protocol_names: Vec<String> = protocols.iter().filter_map(|proto_num| {
                state.protocol_map.iter().find_map(|(&k, &v)| if &v == proto_num { Some(k.to_string()) } else { None })
            }).collect();
            info!("Loaded blocked protocols from database: {:?}", protocol_names);
            Json(protocol_names)
        },
        Err(e) => {
            warn!("Failed to load blocked protocols from database: {}", e);
            Json(vec![])
        }
    }
}

async fn get_protocols_handler(
    Extension(state): Extension<AppState>,
) -> Json<StdHashMap<&'static str, u64>> {
    Json((*state.protocol_map).clone())
}

async fn get_dropped_stats_handler(
    Extension(state): Extension<AppState>,
) -> Json<StdHashMap<String, Vec<(String, u64)>>> {
    let dropped_ip_counts_map = state.blocklist_map_state.dropped_ip_counts.lock().unwrap();
    let dropped_protocol_counts_map = state.blocklist_map_state.dropped_protocol_counts.lock().unwrap();

    let mut dropped_ip_counts = Vec::new();
    for entry in dropped_ip_counts_map.iter() {
        if let Ok((ip, count)) = entry {
            let ip_str = Ipv4Addr::from(ip.clone()).to_string();
            dropped_ip_counts.push((ip_str, count.clone()));
        }
    }

    let mut dropped_proto_counts = Vec::new();
    for entry in dropped_protocol_counts_map.iter() {
        if let Ok((proto, count)) = entry {
            let proto_name = state.protocol_map.iter()
                .find_map(|(&k, &v)| if v == proto.clone() { Some(k.to_string()) } else { None })
                .unwrap_or_else(|| format!("Unknown ({})", proto));
            dropped_proto_counts.push((proto_name, count.clone()));
        }
    }

    let stats: StdHashMap<String, Vec<(String, u64)>> = vec![
        ("dropped_ips".to_string(), dropped_ip_counts),
        ("dropped_protocols".to_string(), dropped_proto_counts),
    ].into_iter().collect();

    Json(stats)
}



async fn charts_handler() -> Html<String> {
    let html = include_str!("../../static/charts.html");
    Html(html.to_string())
}

