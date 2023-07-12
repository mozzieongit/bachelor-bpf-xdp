#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp(name = "ba_ebpf_try1")]
pub fn ba_ebpf_try1(ctx: XdpContext) -> u32 {
    match try_ba_ebpf_try1(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_ba_ebpf_try1(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let t: &str;
    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            t = "tcp";
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            t = "udp";
            u16::from_be(unsafe { (*udphdr).source })
        }
        IpProto::Icmp => {
            t = "udp";
            0
        }
        _ => return Ok(xdp_action::XDP_PASS),
        // _ => return Ok(xdp_action::XDP_DROP),
    };

    let action = if block_ip(source_addr) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    info!(
        &ctx,
        "SRC IP: {} - {}.{}.{}.{}, SRC PORT: {}, TYPE: {}, ACTION: {}",
        source_addr,
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        source_port,
        t,
        action
    );

    Ok(action)
}
