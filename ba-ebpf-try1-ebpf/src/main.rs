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
    tcp::TcpHdr,
    udp::UdpHdr,
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
    let mut udphdr: Option<*mut UdpHdr> = None;
    let dest_port = match proto {
        IpProto::Udp => {
            udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            if udphdr.is_some() {
                Some(u16::from_be(unsafe { (*udphdr.unwrap()).dest }))
            } else {
                None
            }
        }
        _ => None,
    };

    info!(
        &ctx,
        "_START: from {}.{}.{}.{} to {}.{}.{}.{}:{}, checksum: {} (inpkt:{})",
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        (dest_addr >> 24) & 0xff,
        (dest_addr >> 16) & 0xff,
        (dest_addr >> 8) & 0xff,
        dest_addr & 0xff,
        dest_port.unwrap_or(0),
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
    let action = if proto == IpProto::Udp
        && source_addr == _ip_flood_10
        && dest_addr == _ip_xdp2_10
        && udphdr.is_some()
        && dest_port == Some(5202)
    {
        let csum_ip: u16;
        unsafe {
            // (*ipv4hdr).src_addr = u32::to_be(_ip_flood);
            // (*ipv4hdr).dst_addr = u32::to_be(_ip_xdp1);
            // (*ipv4hdr).src_addr = u32::to_be(u32::from_be_bytes([172,17,0,1]));
            // let new_dst_addr = u32::from_be_bytes([172, 17, 0, 2]);
            let new_dst_addr = _ip_xdp2;
            (*ipv4hdr).dst_addr = u32::to_be(new_dst_addr);
            // replace first half of address check
            let udp_check_orig: u16 = u16::from_be((*udphdr.unwrap()).check);
            let udp_check: u16 = csum_replace(
                udp_check_orig,
                (dest_addr >> 16) as u16,
                (new_dst_addr >> 16) as u16,
            );

            // replace second half of address
            let udp_check: u16 = csum_replace(
                udp_check,
                (dest_addr & 0xffff) as u16,
                (new_dst_addr & 0xffff) as u16,
            );

            // replace port in checksum
            let udp_check: u16 = csum_replace(
                udp_check,
                5202,
                5201,
            );

            (*udphdr.unwrap()).dest = u16::to_be(5201);

            // write new checksum back into udp header
            (*udphdr.unwrap()).check = u16::to_be(udp_check);
            csum_ip = checksum(&ctx)?;
            (*ipv4hdr).check = u16::to_be(csum_ip);
        }
        // info!(
        // &ctx,
        // "_MID: changeing packet: {}.{}.{}.{} => {}.{}.{}.{} to {}.{}.{}.{} => {}.{}.{}.{} (new check: {})",
        // (source_addr >> 24) & 0xff,
        // (source_addr >> 16) & 0xff,
        // (source_addr >> 8) & 0xff,
        // source_addr & 0xff,
        // (dest_addr >> 24) & 0xff,
        // (dest_addr >> 16) & 0xff,
        // (dest_addr >> 8) & 0xff,
        // dest_addr & 0xff,
        // (_ip_flood >> 24) & 0xff,
        // (_ip_flood >> 16) & 0xff,
        // (_ip_flood >> 8) & 0xff,
        // _ip_flood & 0xff,
        // (_ip_xdp1 >> 24) & 0xff,
        // (_ip_xdp1 >> 16) & 0xff,
        // (_ip_xdp1 >> 8) & 0xff,
        // _ip_xdp1 & 0xff,
        // csum
        // );
        // // docker0 => 0
        // // eno1 => 1
        // // ens3f1 => 2
        // index 13 // docker0 // bridge not supported
        // index 2  // eno1    // tg3 driver not supported
        // index 7  // ens3f1
        // let ifindex = *(unsafe { IFINDEX.get(&1).unwrap_or(&0) });
        // 20 is veth für iperf3
        // let ifindex = 28u32; // veth
        // let ifindex = 42u32;
        // unsafe { bpf_redirect(ifindex, 0).try_into().unwrap() }
        // xdp_action::XDP_TX
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_PASS
    };

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let dest_port = match proto {
        IpProto::Udp => {
            udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            if udphdr.is_some() {
                Some(u16::from_be(unsafe { (*udphdr.unwrap()).dest }))
            } else {
                None
            }
        }
        _ => None,
    };

    info!(
        &ctx,
        "_END: from {}.{}.{}.{} to {}.{}.{}.{}:{}, action: {}",
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        (dest_addr >> 24) & 0xff,
        (dest_addr >> 16) & 0xff,
        (dest_addr >> 8) & 0xff,
        dest_addr & 0xff,
        dest_port.unwrap_or(0),
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
    //     info!(
    //         ctx,
    //         " checksum: WORDS in calc
    // word0: {} version+ihl+dscp/tos
    // word1: {} total length
    // word2: {} id
    // word3: {} flags+frag_off
    // word4: {} ttl({})+proto({})
    // word5: {} checksum
    // word6: {} src_addr/1
    // word7: {} src_addr/2
    // word8: {} dst_addr/1
    // word9: {} dst_addr/2",
    //         word0,
    //         word1,
    //         word2,
    //         word3,
    //         word4,
    //         ttl,
    //         proto,
    //         word5,
    //         word6,
    //         word7,
    //         word8,
    //         word9
    //     );

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

    while sum > 0xffff {
        sum -= 0xffff;
    }

    let res = !(sum as u16);

    info!(ctx, "  checksum: new: {} (before: {})", res, orig_check);

    Ok(res)
}

// unsafe fn udp_checksum(ctx: &XdpContext) -> Result<u16, ()> {
//     let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
//     let proto: u16 = u16::from_be((*ipv4hdr).proto as u16);
//     let src_addr: u32 = u32::from_be((*ipv4hdr).src_addr);
//     let dst_addr: u32 = u32::from_be((*ipv4hdr).dst_addr);

//     let udphdr: *const UdpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
//     let udp_len = u16::from_be(unsafe { (*udphdr).len });
//     let dst_port = u16::from_be(unsafe { (*udphdr).dest });
//     let src_port = u16::from_be(unsafe { (*udphdr).source });

//     let data: *const u16 = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

//     let word0: u16 = (src_addr >> 16) as u16;
//     let word1: u16 = src_addr as u16;
//     let word2: u16 = (dst_addr >> 16) as u16;
//     let word3: u16 = dst_addr as u16;
//     let word4: u16 = proto;
//     let word5: u16 = udp_len;
//     let word6: u16 = src_port;
//     let word7: u16 = dst_port;
//     let word8: u16 = udp_len;
//     let word9: u16 = 0; // checksum
//     let word10: u16 = data; // AAAAHHHH
//     (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags)
// }

fn csum16_add(csum: u16, addend: u16) -> u16 {
    let res: u16 = csum;
    let res = res.wrapping_add(addend);
    if res < addend {
        res + 1
    } else {
        res
    }
}
// from xdp-tutorial advanced03-AF_XDP/af_xdp_user.c
// static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
//     uint16_t res = (uint16_t)csum;

//     res += (__u16)addend;
//     return (__sum16)(res + (res < (__u16)addend));
// }

fn csum16_sub(csum: u16, addend: u16) -> u16 {
    csum16_add(csum, !addend)
}
// static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
//     return csum16_add(csum, ~addend);
// }

fn csum_replace(check: u16, old: u16, new: u16) -> u16 {
    !csum16_add(csum16_sub(!check, old), new)
}
// static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new) {
//     *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
// }
