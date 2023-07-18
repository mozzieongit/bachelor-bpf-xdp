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
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {}
        IpProto::Tcp => {}
        _ => return Ok(xdp_action::XDP_PASS)
    }

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let proto = unsafe { (*ipv4hdr).proto };
    let mut udphdr: Option<*mut UdpHdr> = None;
    let mut tcphdr: Option<*mut TcpHdr> = None;
    let dest_port = match proto {
        IpProto::Udp => {
            udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            u16::from_be(unsafe { (*udphdr.unwrap()).dest })
        }
        IpProto::Tcp => {
            tcphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            u16::from_be(unsafe { (*tcphdr.unwrap()).dest })
        }
        _ => 0,
        // _ => return Ok(xdp_action::XDP_PASS),
    };
    let src_port = match proto {
        IpProto::Udp => {
            udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            u16::from_be(unsafe { (*udphdr.unwrap()).source })
        }
        IpProto::Tcp => {
            tcphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            u16::from_be(unsafe { (*tcphdr.unwrap()).source })
        }
        _ => 0,
        // _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(
        &ctx,
        "_START: from {}.{}.{}.{}:{} to {}.{}.{}.{}:{}",
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        src_port,
        (dest_addr >> 24) & 0xff,
        (dest_addr >> 16) & 0xff,
        (dest_addr >> 8) & 0xff,
        dest_addr & 0xff,
        dest_port
    );

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
    // let new_dst_addr = u32::from_be_bytes([172, 17, 0, 2]);
    // let new_src_addr = u32::from_be_bytes([172, 17, 0, 1]);
    let action = match proto {
        // IpProto::Udp => {
        //     if source_addr == _ip_docker && dest_addr == _ip_flood_10 && src_port == Some(5201) {
        //         let csum_ip: u16;
        //         unsafe {
        //             // (*ipv4hdr).dst_addr = u32::to_be(new_dst_addr);

        //             let udp_check_orig: u16 = u16::from_be((*udphdr.unwrap()).check);

        //             // // REPLACE DESTINATION IP CHECKSUM PART
        //             // // replace first half of address check
        //             // let udp_check: u16 = csum_replace(
        //             //     udp_check_orig,
        //             //     (dest_addr >> 16) as u16,
        //             //     (new_dst_addr >> 16) as u16,
        //             // );
        //             // // replace second half of address
        //             // let udp_check: u16 = csum_replace(
        //             //     udp_check,
        //             //     (dest_addr & 0xffff) as u16,
        //             //     (new_dst_addr & 0xffff) as u16,
        //             // );

        //             // REPLACE DEST_PORT CHECKSUM PART
        //             // replace port in checksum
        //             let udp_check: u16 = csum_replace(udp_check_orig, 5201, 5202);

        //             // set source port back to original
        //             (*udphdr.unwrap()).dest = u16::to_be(5202);

        //             (*ipv4hdr).src_addr = u32::to_be(new_src_addr);

        //             // REPLACE SOURCE IP CHECKSUM PART
        //             // replace first half of address check
        //             let udp_check: u16 = csum_replace(
        //                 udp_check,
        //                 (source_addr >> 16) as u16,
        //                 (new_src_addr >> 16) as u16,
        //             );

        //             // replace second half of address
        //             let udp_check: u16 = csum_replace(
        //                 udp_check,
        //                 (source_addr & 0xffff) as u16,
        //                 (new_src_addr & 0xffff) as u16,
        //             );

        //             // write new checksum back into udp header
        //             (*udphdr.unwrap()).check = u16::to_be(udp_check);
        //             csum_ip = checksum(&ctx)?;
        //             (*ipv4hdr).check = u16::to_be(csum_ip);

        //             // container eth0 mac 02:42:ac:11:00:02
        //             // xdp2 ens3f1 mac a0:36:9f:f5:99:06
        //             (*ethhdr).src_addr[0] = 0xa0;
        //             (*ethhdr).src_addr[1] = 0x36;
        //             (*ethhdr).src_addr[2] = 0x9f;
        //             (*ethhdr).src_addr[3] = 0xf5;
        //             (*ethhdr).src_addr[4] = 0x99;
        //             (*ethhdr).src_addr[5] = 0x06;
        //         }
        //         // let ifidx_ens3f1 = 7
        //         // let ifindex = *(unsafe { IFINDEX.get(&0).unwrap_or(&0) });
        //         // // index 7  // ens3f1
        //         let ifindex = 7u32;
        //         unsafe { bpf_redirect(ifindex, 0).try_into().unwrap() }
        //     } else {
        //         xdp_action::XDP_PASS
        //     }
        // }
        IpProto::Tcp => {
            if source_addr == _ip_docker && (dest_addr == _ip_flood_10 || dest_addr == _ip_router) && src_port == 5555 {
                let csum_ip: u16;
                unsafe {
                    (*ipv4hdr).dst_addr = u32::to_be(new_dst_addr);

                    let tcp_check_orig: u16 = u16::from_be((*tcphdr.unwrap()).check);

                    // REPLACE DESTINATION IP CHECKSUM PART
                    // replace first half of address check
                    let tcp_check: u16 = csum_replace(
                        tcp_check_orig,
                        (dest_addr >> 16) as u16,
                        (new_dst_addr >> 16) as u16,
                    );
                    // replace second half of address
                    let tcp_check: u16 = csum_replace(
                        tcp_check,
                        (dest_addr & 0xffff) as u16,
                        (new_dst_addr & 0xffff) as u16,
                    );

                    // REPLACE SRC_PORT CHECKSUM PART
                    // replace port in checksum
                    let tcp_check: u16 = csum_replace(tcp_check, 5555, 5202);

                    (*tcphdr.unwrap()).source = u16::to_be(5202);

                    (*ipv4hdr).src_addr = u32::to_be(new_src_addr);

                    // REPLACE SOURCE IP CHECKSUM PART
                    // replace first half of address check
                    let tcp_check: u16 = csum_replace(
                        tcp_check,
                        (source_addr >> 16) as u16,
                        (new_src_addr >> 16) as u16,
                    );

                    // replace second half of address
                    let tcp_check: u16 = csum_replace(
                        tcp_check,
                        (source_addr & 0xffff) as u16,
                        (new_src_addr & 0xffff) as u16,
                    );

                    // write new checksum back into tcp header
                    (*tcphdr.unwrap()).check = u16::to_be(tcp_check);
                    csum_ip = checksum(&ctx)?;
                    (*ipv4hdr).check = u16::to_be(csum_ip);

                    // container eth0 mac 02:42:ac:11:00:02
                    // xdp2 ens3f1 mac a0:36:9f:f5:99:06
                    (*ethhdr).src_addr[0] = 0xa0;
                    (*ethhdr).src_addr[1] = 0x36;
                    (*ethhdr).src_addr[2] = 0x9f;
                    (*ethhdr).src_addr[3] = 0xf5;
                    (*ethhdr).src_addr[4] = 0x99;
                    (*ethhdr).src_addr[5] = 0x06;

                    // flood enp2s0f1 a0:36:9f:f5:8a:4a
                    (*ethhdr).dst_addr[0] = 0xa0;
                    (*ethhdr).dst_addr[1] = 0x36;
                    (*ethhdr).dst_addr[2] = 0x9f;
                    (*ethhdr).dst_addr[3] = 0xf5;
                    (*ethhdr).dst_addr[4] = 0x8a;
                    (*ethhdr).dst_addr[5] = 0x4a;
                }
                // let ifidx_ens3f1 = 7
                // let ifindex = *(unsafe { IFINDEX.get(&0).unwrap_or(&0) });
                // // index 7  // ens3f1
                let ifindex = 7u32;
                unsafe { bpf_redirect(ifindex, 0).try_into().unwrap() }
            } else {
                xdp_action::XDP_PASS
            }
        }
        _ => xdp_action::XDP_PASS,
    };

    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let dest_port = match proto {
        IpProto::Udp => {
            udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            Some(u16::from_be(unsafe { (*udphdr.unwrap()).dest }))
        }
        IpProto::Tcp => {
            tcphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            Some(u16::from_be(unsafe { (*tcphdr.unwrap()).dest }))
        }
        _ => None,
    };
    let src_port = match proto {
        IpProto::Udp => {
            udphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            u16::from_be(unsafe { (*udphdr.unwrap()).source })
        }
        IpProto::Tcp => {
            tcphdr = Some(ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?);
            u16::from_be(unsafe { (*tcphdr.unwrap()).source })
        }
        _ => 0,
        // _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(
        &ctx,
        "_END: from {}.{}.{}.{}:{} to {}.{}.{}.{}:{}, action: {}",
        (source_addr >> 24) & 0xff,
        (source_addr >> 16) & 0xff,
        (source_addr >> 8) & 0xff,
        source_addr & 0xff,
        src_port,
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
