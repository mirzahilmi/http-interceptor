#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[map(name = "HTTP_PACKET_COUNTER")]
static HTTP_PACKET_COUNTER: Array<u64> = Array::with_max_entries(1, 0);

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

#[xdp]
pub fn program(ctx: XdpContext) -> u32 {
    let _ = try_program(ctx);
    xdp_action::XDP_PASS
}

fn try_program(ctx: XdpContext) -> Result<(), ()> {
    debug!(&ctx, "http_rater: received a packet");

    let eth_header: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*eth_header).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Err(()),
    }

    let ipv4_header: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    match unsafe { (*ipv4_header).proto } {
        IpProto::Tcp => {}
        _ => return Err(()),
    }
    let tcp_header: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    // black magic length
    let tcp_header_len = (unsafe { (*tcp_header).doff() } as usize) * 4;
    let http_data = ptr_at::<[u8; 16]>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len)?;
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

    unsafe {
        let counter = HTTP_PACKET_COUNTER.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    debug!(&ctx, "http_rater: count up by 1");

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
// An eBPF-compatible panic handler is provided because eBPF programs cannot use the default panic behavior.
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
