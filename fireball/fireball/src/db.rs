use rusqlite::{params, Connection, Result};
use log::info;

pub fn initialize_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY,
            ip_address TEXT NOT NULL UNIQUE
        )",
        params![],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocked_protocols (
            id INTEGER PRIMARY KEY,
            protocol INTEGER NOT NULL UNIQUE
        )",
        params![],
    )?;
    info!("Database initialized");
    Ok(())
}

pub fn add_blocked_ip(conn: &Connection, ip: &str) -> Result<()> {
    info!("Adding blocked IP: {}", ip);
    conn.execute(
        "INSERT INTO blocked_ips (ip_address) VALUES (?1)",
        params![ip],
    )?;
    Ok(())
}

pub fn remove_blocked_ip(conn: &Connection, ip: &str) -> Result<()> {
    info!("Removing blocked IP: {}", ip);
    conn.execute(
        "DELETE FROM blocked_ips WHERE ip_address = ?1",
        params![ip],
    )?;
    Ok(())
}

pub fn get_blocked_ips(conn: &Connection) -> Result<Vec<String>> {
    info!("Retrieving blocked IPs from database");
    let mut stmt = conn.prepare("SELECT ip_address FROM blocked_ips")?;
    let ip_iter = stmt.query_map(params![], |row| {
        let ip: String = row.get(0)?;
        info!("Retrieved blocked IP from row: {}", ip);
        Ok(ip)
    })?;
    let mut ips = Vec::new();
    for ip in ip_iter {
        ips.push(ip?);
    }
    info!("Blocked IPs retrieved: {:?}", ips);
    Ok(ips)
}

pub fn add_blocked_protocol(conn: &Connection, protocol: u64) -> Result<()> {
    info!("Adding blocked protocol: {}", protocol);
    conn.execute(
        "INSERT INTO blocked_protocols (protocol) VALUES (?1)",
        params![protocol],
    )?;
    Ok(())
}

pub fn remove_blocked_protocol(conn: &Connection, protocol: u64) -> Result<()> {
    info!("Removing blocked protocol: {}", protocol);
    conn.execute(
        "DELETE FROM blocked_protocols WHERE protocol = ?1",
        params![protocol],
    )?;
    Ok(())
}

pub fn get_blocked_protocols(conn: &Connection) -> Result<Vec<u64>> {
    info!("Retrieving blocked protocols from database");
    let mut stmt = conn.prepare("SELECT protocol FROM blocked_protocols")?;
    let protocol_iter = stmt.query_map(params![], |row| {
        let protocol: u64 = row.get(0)?;
        info!("Retrieved blocked protocol from row: {}", protocol);
        Ok(protocol)
    })?;
    let mut protocols = Vec::new();
    for protocol in protocol_iter {
        protocols.push(protocol?);
    }
    info!("Blocked protocols retrieved: {:?}", protocols);
    Ok(protocols)
}
