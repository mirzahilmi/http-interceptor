#![no_std]
#![no_main]
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
use program_ebpf::ptr_at;

#[map(name = "HTTP_PACKET_COUNTER")]
static HTTP_PACKET_COUNTER: Array<u64> = Array::with_max_entries(1, 0);

#[xdp]
pub fn program(ctx: XdpContext) -> u32 {
    let _ = try_program(ctx);
    xdp_action::XDP_PASS
}

fn try_program(ctx: XdpContext) -> Result<(), ()> {
    debug!(&ctx, "http_rater: packet captured");

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

    // Get TCP data offset (header length in 32-bit words)
    let tcp_data_offset = unsafe { (*tcp_header).doff() };

    // Use a lookup table instead of multiplication to help the verifier
    // This maps data offset values (5-15) to byte lengths (20-60)
    let tcp_header_len = match tcp_data_offset {
        5 => 20,
        6 => 24,
        7 => 28,
        8 => 32,
        9 => 36,
        10 => 40,
        11 => 44,
        12 => 48,
        13 => 52,
        14 => 56,
        15 => 60,
        _ => return Err(()),
    };

    let http_offset = EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len;

    let http_data: *const [u8; 4] = ptr_at(&ctx, http_offset)?;
    let data = unsafe { *http_data };

    let http_methods = [
        "GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "CONN", "TRAC",
    ];

    if !http_methods
        .iter()
        .any(|method| data.starts_with(method.as_bytes()))
    {
        return Err(());
    }

    // Increment counter
    unsafe {
        let counter = HTTP_PACKET_COUNTER.get_ptr_mut(0).ok_or(())?;
        *counter += 1;
    }
    debug!(&ctx, "http_rater: http packet identified");

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
