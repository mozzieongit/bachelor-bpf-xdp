#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    helpers::bpf_redirect,
    macros::{map, xdp},
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp(name = "ba_ebpf_veth")]
pub fn ba_ebpf_veth(ctx: XdpContext) -> u32 {
    match try_ba_ebpf_veth(ctx) {
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

fn try_ba_ebpf_veth(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
    let proto = unsafe { (*ipv4hdr).proto };
    match proto {
        IpProto::Udp => {}
        IpProto::Tcp => {}
        _ => return Ok(xdp_action::XDP_PASS)
    }

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let ip4_check_orig = u16::from_be(unsafe { (*ipv4hdr).check });
    let mut udphdr: Option<*mut UdpHdr> = None;
    let mut tcphdr: Option<*mut TcpHdr> = None;
    let src_port = match proto {
        IpProto::Udp => {
            udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            Some(u16::from_be(unsafe { (*udphdr.unwrap()).source }))
        }
        IpProto::Tcp => {
            tcphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            Some(u16::from_be(unsafe { (*tcphdr.unwrap()).source }))
        }
        _ => None,
    };

    // info!(
    //     &ctx,
    //     "_START: from {}.{}.{}.{}:{} to {}.{}.{}.{}:{}",
    //     (source_addr >> 24) & 0xff,
    //     (source_addr >> 16) & 0xff,
    //     (source_addr >> 8) & 0xff,
    //     source_addr & 0xff,
    //     src_port,
    //     (dest_addr >> 24) & 0xff,
    //     (dest_addr >> 16) & 0xff,
    //     (dest_addr >> 8) & 0xff,
    //     dest_addr & 0xff,
    //     dest_port
    // );

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
    let _ip_docker = u32::from_be_bytes([172, 17, 0, 2]);
    let _ip_router = u32::from_be_bytes([172, 17, 0, 1]);
    let new_dst_addr = _ip_flood_10;
    let new_src_addr = _ip_xdp2_10;
    let ifindex = 7u32;
    let docker_src_port = 4444u16;
    let action = match proto {
        IpProto::Udp => {
            if source_addr == _ip_docker && dest_addr == _ip_router && src_port == Some(docker_src_port) {
                unsafe {
                    let mut udp_check: u16 = u16::from_be((*udphdr.unwrap()).check);
                    let mut ip4_check: u16 = ip4_check_orig;

                    // replace destination ip
                    (*ipv4hdr).dst_addr = u32::to_be(new_dst_addr);
                    ip4_check = csum_replace_u32(ip4_check, dest_addr, new_dst_addr);
                    udp_check = csum_replace_u32(udp_check, dest_addr, new_dst_addr);

                    // replace source ip
                    (*ipv4hdr).src_addr = u32::to_be(new_src_addr);
                    ip4_check = csum_replace_u32(ip4_check, source_addr, new_src_addr);
                    udp_check = csum_replace_u32(udp_check, source_addr, new_src_addr);

                    // write new checksum back into headers
                    (*udphdr.unwrap()).check = u16::to_be(udp_check);
                    (*ipv4hdr).check = u16::to_be(ip4_check);

                    // container eth0 mac 02:42:ac:11:00:02
                    // xdp2 ens3f1 mac a0:36:9f:f5:99:06
                    // flood enp2s0f1 mac a0:36:9f:f5:8a:4a
                    set_mac(&mut (*ethhdr).src_addr, [0xa0, 0x36, 0x9f, 0xf5, 0x99, 0x06]);
                    set_mac(&mut (*ethhdr).dst_addr, [0xa0, 0x36, 0x9f, 0xf5, 0x8a, 0x4a]);
                }
                // let ifidx_ens3f1 = 7
                // let ifindex = *(unsafe { IFINDEX.get(&0).unwrap_or(&0) });
                // // index 7  // ens3f1
                unsafe { bpf_redirect(ifindex, 0).try_into().unwrap() }
            } else {
                xdp_action::XDP_PASS
            }
        }
        IpProto::Tcp => {
            if source_addr == _ip_docker && dest_addr == _ip_router && src_port == Some(docker_src_port) {
                unsafe {
                    let mut tcp_check: u16 = u16::from_be((*tcphdr.unwrap()).check);
                    let mut ip4_check: u16 = ip4_check_orig;

                    (*ipv4hdr).dst_addr = u32::to_be(new_dst_addr);
                    ip4_check = csum_replace_u32(ip4_check, dest_addr, new_dst_addr);
                    tcp_check = csum_replace_u32(tcp_check, dest_addr, new_dst_addr);

                    (*ipv4hdr).src_addr = u32::to_be(new_src_addr);
                    ip4_check = csum_replace_u32(ip4_check, source_addr, new_src_addr);
                    tcp_check = csum_replace_u32(tcp_check, source_addr, new_src_addr);

                    // write new checksum back into tcp header
                    (*tcphdr.unwrap()).check = u16::to_be(tcp_check);
                    (*ipv4hdr).check = u16::to_be(ip4_check);

                    // container eth0 mac 02:42:ac:11:00:02
                    // xdp2 ens3f1 mac a0:36:9f:f5:99:06
                    set_mac(&mut (*ethhdr).src_addr, [0xa0, 0x36, 0x9f, 0xf5, 0x99, 0x06]);

                    // flood enp2s0f1 a0:36:9f:f5:8a:4a
                    set_mac(&mut (*ethhdr).dst_addr, [0xa0, 0x36, 0x9f, 0xf5, 0x8a, 0x4a]);
                }
                // let ifidx_ens3f1 = 7
                // let ifindex = *(unsafe { IFINDEX.get(&0).unwrap_or(&0) });
                unsafe { bpf_redirect(ifindex, 0).try_into().unwrap() }
            } else {
                xdp_action::XDP_PASS
            }
        }
        _ => xdp_action::XDP_PASS,
    };

    // let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    // let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    // let dest_port = match proto {
    //     IpProto::Udp => {
    //         udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
    //         Some(u16::from_be(unsafe { (*udphdr.unwrap()).dest }))
    //     }
    //     IpProto::Tcp => {
    //         tcphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
    //         Some(u16::from_be(unsafe { (*tcphdr.unwrap()).dest }))
    //     }
    //     _ => None,
    // };
    // let src_port = match proto {
    //     IpProto::Udp => {
    //         udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
    //         u16::from_be(unsafe { (*udphdr.unwrap()).source })
    //     }
    //     IpProto::Tcp => {
    //         tcphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
    //         u16::from_be(unsafe { (*tcphdr.unwrap()).source })
    //     }
    //     _ => 0,
    //     // _ => return Ok(xdp_action::XDP_PASS),
    // };

    // info!(
    //     &ctx,
    //     "_END: from {}.{}.{}.{}:{} to {}.{}.{}.{}:{}, action: {}",
    //     (source_addr >> 24) & 0xff,
    //     (source_addr >> 16) & 0xff,
    //     (source_addr >> 8) & 0xff,
    //     source_addr & 0xff,
    //     src_port,
    //     (dest_addr >> 24) & 0xff,
    //     (dest_addr >> 16) & 0xff,
    //     (dest_addr >> 8) & 0xff,
    //     dest_addr & 0xff,
    //     dest_port.unwrap_or(0),
    //     action
    // );

    Ok(action)
}

fn csum_replace_u32(mut check: u16, old: u32, new: u32) -> u16 {
    check = csum_replace(check, (old >> 16) as u16, (new >> 16) as u16);
    check = csum_replace(check, (old & 0xffff) as u16, (new & 0xffff) as u16);
    check
}

fn set_mac(hdr_part: &mut [u8; 6], new_mac: [u8; 6]) {
    hdr_part[0] = new_mac[0];
    hdr_part[1] = new_mac[1];
    hdr_part[2] = new_mac[2];
    hdr_part[3] = new_mac[3];
    hdr_part[4] = new_mac[4];
    hdr_part[5] = new_mac[5];
}

/*******************************************************************************
* Title: XDP Tutorial
* Author: Eelco Chaudron
* Date: 2019-08-16
* Availability: https://github.com/xdp-project/xdp-tutorial
* **************************************************************************/
// from xdp-tutorial:advanced03-AF_XDP/af_xdp_user.c
// static inline __sum16 csum16_add(__sum16 csum, __be16 addend) {
//     uint16_t res = (uint16_t)csum;

//     res += (__u16)addend;
//     return (__sum16)(res + (res < (__u16)addend));
// }
// static inline __sum16 csum16_sub(__sum16 csum, __be16 addend) {
//     return csum16_add(csum, ~addend);
// }
// static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new) {
//     *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
// }
// The algorithm can also be found in RFC 1624.
// The Code was modified to fit into rust syntax.

fn csum16_add(csum: u16, addend: u16) -> u16 {
    let res: u16 = csum;
    let res = res.wrapping_add(addend);
    if res < addend {
        res + 1
    } else {
        res
    }
}

fn csum16_sub(csum: u16, addend: u16) -> u16 {
    csum16_add(csum, !addend)
}

fn csum_replace(check: u16, old: u16, new: u16) -> u16 {
    !csum16_add(csum16_sub(!check, old), new)
}
