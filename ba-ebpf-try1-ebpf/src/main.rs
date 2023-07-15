#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    helpers::bpf_redirect,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

#[map(name = "IFINDEX")]
static mut IFINDEX: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

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

fn try_ba_ebpf_try1(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let orig_check = u16::from_be(unsafe { (*ipv4hdr).check });
    let new_check = unsafe { checksum(&ctx)? };
    let proto = unsafe { (*ipv4hdr).proto };

    info!(
        &ctx,
        "_START: from {}.{}.{}.{} to {}.{}.{}.{}, checksum: {} (inpkt:{})",
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        (dest_addr >> 24) & 0xff,
        (dest_addr >> 16) & 0xff,
        (dest_addr >> 8) & 0xff,
        dest_addr & 0xff,
        new_check,
        orig_check
    );

    // if orig_check != new_check {
    // info!(&ctx, "DAMN");
    // return Ok(xdp_action::XDP_ABORTED);
    // }

    // 194.94.217.30 (xdp1)  = 0xc25ed91e = 3260995870  (tcpdump)
    // 194.94.217.31 (flood) = 0xc25ed91f = 3260995871
    // 194.94.217.32 (xdp2)  = 0xc25ed920 = 3260995872
    // 10.1.2.1 (xdp2)  = 0xa010201 = 167838209
    // 10.1.2.2 (flood) = 0xa010202 = 167838210  (ping src)
    let _ip_xdp1: u32 = 0xc25ed91e;
    let _ip_flood: u32 = 0xc25ed91f;
    let _ip_xdp2: u32 = 0xc25ed920;
    let _ip_xdp2_10: u32 = 0xa010201;
    let _ip_flood_10: u32 = 0xa010202;
    let action =
        if proto == IpProto::Icmp && source_addr == _ip_flood_10 && dest_addr == _ip_xdp2_10 {
            let csum: u16;
            unsafe {
                (*ipv4hdr).src_addr = u32::to_be(_ip_flood);
                (*ipv4hdr).dst_addr = u32::to_be(_ip_xdp1);
                csum = checksum(&ctx)?;
                (*ipv4hdr).check = u16::to_be(csum);
            }
            info!(
                &ctx,
                "_MID: changeing packet: {}.{}.{}.{} => {}.{}.{}.{} to {}.{}.{}.{} => {}.{}.{}.{} (new check: {})",
                (source_addr >> 24) & 0xff,
                (source_addr >> 16) & 0xff,
                (source_addr >> 8) & 0xff,
                source_addr & 0xff,
                (dest_addr >> 24) & 0xff,
                (dest_addr >> 16) & 0xff,
                (dest_addr >> 8) & 0xff,
                dest_addr & 0xff,
                (_ip_flood >> 24) & 0xff,
                (_ip_flood >> 16) & 0xff,
                (_ip_flood >> 8) & 0xff,
                _ip_flood & 0xff,
                (_ip_xdp1 >> 24) & 0xff,
                (_ip_xdp1 >> 16) & 0xff,
                (_ip_xdp1 >> 8) & 0xff,
                _ip_xdp1 & 0xff,
                csum
            );
            // // docker0 => 0
            // // eno1 => 1
            // // ens3f1 => 2
            // (0,16), // docker0
            // (1,2), // eno1
            // (2,7) // ens3f1
            // let ifindex = *(unsafe { IFINDEX.get(&1).unwrap_or(&0) });
            let ifindex = 2u32;
            let flags = 0;
            let a = unsafe { bpf_redirect(ifindex, flags).try_into().unwrap() };
            info!(&ctx, " ======> {}", a);
            a
            // xdp_action::XDP_REDIRECT
            // xdp_action::XDP_TX
            // xdp_action::XDP_PASS
        } else {
            xdp_action::XDP_PASS
        };

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    info!(
        &ctx,
        "_END: from {}.{}.{}.{} to {}.{}.{}.{}, action: {}",
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        (dest_addr >> 24) & 0xff,
        (dest_addr >> 16) & 0xff,
        (dest_addr >> 8) & 0xff,
        dest_addr & 0xff,
        action
    );

    Ok(action)
}

#[inline(always)]
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

    info!(ctx, "  checksum: packet data: v:{}, ihl:{}, dscp_ecn:{}, tot_len:{}, id:{}, flags:{}, frag_off:{}, ttl:{}, proto:{}, check:{}, src:{}, dst:{}",
          version, ihl, dcp_ecn, tot_len, id, flags, frag_off, ttl, proto, check, src_addr, dst_addr);

    // 16 bit one's complement of the one's complement sum of all 16 bit words in the header
    let word0: u16 = ((version as u16) << 12) + ((ihl as u16) << 8) + (dcp_ecn as u16);
    let word1: u16 = tot_len;
    let word2: u16 = id;
    let word3: u16 = ((flags as u16) << 13) | frag_off; // flags not present in Ipv4Hdr?...
    let word4: u16 = ((ttl as u16) << 8) + proto as u16;
    let word5: u16 = 0; // checksum
    let word6: u16 = (src_addr >> 16) as u16;
    let word7: u16 = src_addr as u16;
    let word8: u16 = (dst_addr >> 16) as u16;
    let word9: u16 = dst_addr as u16;
    info!(
        ctx,
        " checksum: WORDS in calc
word0: {} version+ihl+dscp/tos
word1: {} total length
word2: {} id
word3: {} flags+frag_off
word4: {} ttl({})+proto({})
word5: {} checksum
word6: {} src_addr/1
word7: {} src_addr/2
word8: {} dst_addr/1
word9: {} dst_addr/2",
        word0,
        word1,
        word2,
        word3,
        word4,
        ttl,
        proto,
        word5,
        word6,
        word7,
        word8,
        word9
    );

    let mut sum: u32 = word0 as u32
        + word1 as u32
        + word2 as u32
        + word3 as u32
        + word4 as u32
        + word5 as u32
        + word6 as u32
        + word7 as u32
        + word8 as u32
        + word9 as u32;

    // info!(ctx, "  sum: {}", sum);
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

    info!(ctx, "  checksum: new: {} (before: {})", res, orig_check);

    Ok(res)
}
