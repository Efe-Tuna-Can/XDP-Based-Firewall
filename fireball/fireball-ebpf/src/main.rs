#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;

use network_types::{ 
    eth::{EthHdr, EtherType}, 
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map(name = "BLOCKED_IPS")]
static mut BLOCKED_IPS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024, 0);

#[map(name = "PROTOCOL_COUNTS")]
static mut PROTOCOL_COUNTS: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(256, 0);

#[map(name = "BLOCKED_PROTOCOLS")]
static mut BLOCKED_PROTOCOLS: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(256, 0);

#[map(name = "DROPPED_IP_COUNTS")]
static mut DROPPED_IP_COUNTS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);

#[map(name = "DROPPED_PROTOCOL_COUNTS")]
static mut DROPPED_PROTOCOL_COUNTS: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(256, 0);

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[xdp]
pub fn fireball(ctx: XdpContext) -> u32 {
    match try_fireball(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_fireball(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; 
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            info!(&ctx, "IPv4 packet");
        }
        EtherType::Ipv6 => {
            info!(&ctx, "IPv6 packet");
            return Ok(xdp_action::XDP_DROP);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr: u32 = unsafe { (*ipv4hdr).src_addr };
    let proto = unsafe { (*ipv4hdr).proto };
    increment_protocol_count(proto as u64);

    let source_addr_bytes = source_addr.to_be_bytes();
    info!(&ctx, "From address: {}.{}.{}.{}", source_addr_bytes[0], source_addr_bytes[1], source_addr_bytes[2], source_addr_bytes[3]);

    if unsafe { BLOCKED_IPS.get(&source_addr).is_some() } {
        info!(&ctx, "Dropping packet ... From address: {}.{}.{}.{}", source_addr_bytes[0], source_addr_bytes[1], source_addr_bytes[2], source_addr_bytes[3]);
        increment_dropped_ip_count(source_addr);
        return Ok(xdp_action::XDP_DROP);
    }

    if unsafe { BLOCKED_PROTOCOLS.get(&(proto as u64)).is_some() } {
        info!(&ctx, "Dropping packet with blocked protocol: {}", proto as u64);
        increment_dropped_protocol_count(proto as u64);
        return Ok(xdp_action::XDP_DROP);
    }

    let mut dest_port: Option<u16> = None;

    match proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            dest_port = Some(u16::from_be(unsafe { (*tcphdr).dest }));

            if unsafe { BLOCKED_PROTOCOLS.get(&(dest_port.unwrap() as u64)).is_some() } {
                info!(&ctx, "Dropping packet with blocked protocol: {}", dest_port.unwrap() as u64);
                increment_dropped_protocol_count(dest_port.unwrap() as u64);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            dest_port = Some(u16::from_be(unsafe { (*udphdr).dest }));

            if unsafe { BLOCKED_PROTOCOLS.get(&(dest_port.unwrap() as u64)).is_some() } {
                info!(&ctx, "Dropping packet with blocked protocol: {}", dest_port.unwrap() as u64);
                increment_dropped_protocol_count(dest_port.unwrap() as u64);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        _ => {}
    }

    if let Some(port) = dest_port {
        info!(&ctx, "RECEIVED: {} PACKET TO PORT {}", proto as u64, port);
    } else {
        info!(&ctx, "RECEIVED: {} PACKET", proto as u64);
    }

    Ok(xdp_action::XDP_PASS)
}

fn increment_protocol_count(protocol: u64) {
    unsafe {
        let count_ptr = PROTOCOL_COUNTS.get_ptr_mut(&protocol);
        if let Some(count) = count_ptr {
            *count += 1;
        } else {
            PROTOCOL_COUNTS.insert(&protocol, &1, 0).unwrap();
        }
    }
}

fn increment_dropped_ip_count(ip: u32) {
    unsafe {
        let count_ptr = DROPPED_IP_COUNTS.get_ptr_mut(&ip);
        if let Some(count) = count_ptr {
            *count += 1;
        } else {
            DROPPED_IP_COUNTS.insert(&ip, &1, 0).unwrap();
        }
    }
}

fn increment_dropped_protocol_count(protocol: u64) {
    unsafe {
        let count_ptr = DROPPED_PROTOCOL_COUNTS.get_ptr_mut(&protocol);
        if let Some(count) = count_ptr {
            *count += 1;
        } else {
            DROPPED_PROTOCOL_COUNTS.insert(&protocol, &1, 0).unwrap();
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
