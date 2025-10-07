use std::env;

use anyhow::Context;
use aya::{
    maps::Array,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use tracing::{error, info};
#[rustfmt::skip]
use tracing::{debug, warn};
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, metrics::SdkMeterProvider};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    tracing_subscriber::fmt::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("http_rater: remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/program"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("http_rater: failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("program").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("http_rater: failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let otelcol_url = env::var("OTELCOL_URL").expect("http_rater: error: OTELCOL_URL not supplied");
    let node_name = env::var("NODE_NAME").expect("http_rater: error: NODE_NAME not supplied");

    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(otelcol_url)
        .build()?;
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .with_resource(Resource::builder().with_service_name("http_rater").build())
        .build();
    global::set_meter_provider(provider);

    let meter = global::meter("http_rater");
    meter
        .f64_observable_counter("http_packet")
        .with_description("Observable counter of incoming http packets")
        .with_callback(move |observe| {
            // i cannot come up any better for now, fix this thing dude
            let Some(map) = ebpf.map("HTTP_PACKET_COUNTER") else {
                warn!("http_rater: cannot find HTTP_PACKET_COUNTER map");
                return;
            };
            let counters = match Array::<_, u64>::try_from(map) {
                Ok(it) => it,
                Err(e) => {
                    error!("http_rater: error: {e}");
                    return;
                }
            };

            let Ok(count) = counters.get(&0, 0) else {
                return;
            };
            observe.observe(
                count as f64,
                &[KeyValue::new("node_name", node_name.clone())],
            );
        })
        .build();

    let ctrl_c = signal::ctrl_c();
    info!("http_rater: waiting for ctrl-c");
    ctrl_c.await?;
    info!("http_rater: shutting down");

    Ok(())
}
