#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[xdp]
pub fn program(ctx: XdpContext) -> u32 {
    let _ = try_program(ctx);
    xdp_action::XDP_PASS
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

fn try_program(ctx: XdpContext) -> Result<(), ()> {
    debug!(&ctx, "received a packet");

    let eth_header: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*eth_header).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Err(()),
    }

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    match unsafe { (*ipv4_hdr).proto } {
        IpProto::Tcp => {}
        _ => return Err(()),
    }
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    // black magic length
    let tcp_hdr_len = (unsafe { (*tcphdr).doff() } as usize) * 4;
    let http_data = ptr_at::<[u8; 16]>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + tcp_hdr_len)?;
    let data = unsafe { &*http_data };

    if data.len() < 4 {
        return Err(());
    }

    let http_methods = [
        "GET", "POST", "PUT", "HEAD", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE",
    ];
    if !http_methods
        .iter()
        .any(|method| data.starts_with(method.as_bytes()))
    {
        return Err(());
    }

    info!(&ctx, "http_interceptor: http inbound");

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // hangs on panic to be aborted by the kernel
    loop {}
}
