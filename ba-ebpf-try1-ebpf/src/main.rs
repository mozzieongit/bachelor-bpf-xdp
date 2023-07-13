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
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
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

    // let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

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
            t = "icmp";
            0
        }
        _ => return Ok(xdp_action::XDP_PASS),
        // _ => return Ok(xdp_action::XDP_DROP),
    };

    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        IpProto::Icmp => 0,
        _ => return Ok(xdp_action::XDP_PASS),
        // _ => return Ok(xdp_action::XDP_DROP),
    };

    if source_port == 53 || dest_port == 53 || source_addr == 3232257898 {
        return Ok(xdp_action::XDP_PASS)
    }

    let action = if block_ip(source_addr) {
        // xdp_action::XDP_REDIRECT
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_PASS
    };

    unsafe {
        // (*ipv4hdr).src_addr = u32::to_be(2130706435);
        let csum: u16 = u16::to_be(checksum(&ctx)?);
        if csum == (*ipv4hdr).check {
            (*ipv4hdr).check = csum;
        } else {
            return Ok(xdp_action::XDP_DROP)
        }
    }
    info!(
        &ctx,
        "{} from {}.{}.{}.{}:{} to {}.{}.{}.{}:{}, action: {}",
        t,
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        source_port,
        (dest_addr >> 24) & 0xff,
        (dest_addr >> 16) & 0xff,
        (dest_addr >> 8) & 0xff,
        dest_addr & 0xff,
        dest_port,
        action
    );

    Ok(action)
}

unsafe fn checksum(ctx: &XdpContext) -> Result<u16, ()> {
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;

    let version: u8 = u8::from_be((*ipv4hdr).version());
    let ihl: u8 = u8::from_be((*ipv4hdr).ihl());
    let dcp_ecn: u8 = u8::from_be((*ipv4hdr).tos);
    let tot_len: u16 = u16::from_be((*ipv4hdr).tot_len);
    let id: u16 = u16::from_be((*ipv4hdr).id);
    let flags: u8 = ((u16::from_be((*ipv4hdr).frag_off) & 0xe000) >> 13) as u8;
    let frag_off: u16 = u16::from_be((*ipv4hdr).frag_off) & 0x1fff;
    let ttl: u8 = u8::from_be((*ipv4hdr).ttl);
    let proto: u8 = u8::from_be((*ipv4hdr).proto as u8);
    let check: u16 = u16::from_be((*ipv4hdr).check);
    let src_addr: u32 = u32::from_be((*ipv4hdr).src_addr);
    let dst_addr: u32 = u32::from_be((*ipv4hdr).dst_addr);

    let orig_check = check;

    // 16bit | version, ihl, dscp_ecn |
    // 16bit | tot_len |
    // 16bit | id |
    // 16bit | flags, frag_off |
    // 16bit | ttl, protocol |
    // 16bit | checksum |
    // 16bit | src_addr/2 |
    // 16bit | src_addr/2 |
    // 16bit | dst_addr/2 |
    // 16bit | dst_addr/2 |

    info!(ctx, "packet data: v:{}, ihl:{}, dscp_ecn:{}, tot_len:{}, id:{}, flags:{}, frag_off:{}, ttl:{}, proto:{}, check:{}, src:{}, dst:{}",
          version, ihl, dcp_ecn, tot_len, id, flags, frag_off, ttl, proto, check, src_addr, dst_addr);

    // 16 bit one's complement of the one's complement sum of all 16 bit words in the header
    let word0: u16 = ((version as u16) << 12) + ((ihl as u16) << 8) + (dcp_ecn as u16);
    info!(ctx, "  word0: {} dscp+ihl+version", word0);
    let word1: u16 = tot_len;
    info!(ctx, "  word1: {} total length", word1);
    let word2: u16 = id;
    info!(ctx, "  word2: {} id", word2);
    let word3: u16 = ((flags as u16) << 13) | frag_off; // flags not present in Ipv4Hdr?...
    info!(ctx, "  word3: {} flags+frag_off", word3);
    let word4: u16 = ((ttl as u16) << 8) + proto as u16;
    info!(ctx, "  word4: {} proto({})+ttl({})", word4, proto, ttl);
    let word5: u16 = 0; // checksum
    info!(ctx, "  word5: {} checksum", word5);
    let word6: u16 = (src_addr >> 16) as u16;
    info!(ctx, "  word6: {} src_addr/1", word6);
    let word7: u16 = src_addr as u16;
    info!(ctx, "  word7: {} src_addr/2", word7);
    let word8: u16 = (dst_addr >> 16) as u16;
    info!(ctx, "  word8: {} dst_addr/1", word8);
    let word9: u16 = dst_addr as u16;
    info!(ctx, "  word9: {} dst_addr/2", word9);

    let mut sum: u32 = word0 as u32 +
        word1 as u32 +
        word2 as u32 +
        word3 as u32 +
        word4 as u32 +
        word5 as u32 +
        word6 as u32 +
        word7 as u32 +
        word8 as u32 +
        word9 as u32;

    info!(ctx, "  sum: {}", sum);
    while sum > 0xffff {
        sum -= 0xffff;
    }
    // is equal to:
    // while sum > 0xffff {
    //     let carry_over = sum >> 16;
    //     let lower16_bits = sum & 0xffff;
    //     sum = carry_over + lower16_bits;
    // }

    let res = !(sum as u16);

    info!(ctx, "new checksum: {} (before: {})", res, orig_check);

    Ok(res)
}
