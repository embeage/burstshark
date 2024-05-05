use std::error::Error;

use clap::Parser;

use burstshark::capture::{CaptureType, CommonOptions};
use burstshark::output::OutputWriter;

#[derive(Parser, Clone, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Network interface to use for live capture. First non-loopback interface if no interface or file supplied.
    #[clap(short = 'i', long = "interface")]
    interface: Option<String>,

    /// Packet filter in libpcap filter syntax. Merged with default for data packets.
    #[clap(short = 'f', long = "capture-filter", conflicts_with = "infile")]
    capture_filter: Option<String>,

    /// Number of bytes to capture per packet. Default is 96 bytes, enough to capture relevant headers.
    /// A value of 0 captures the entire packet.
    #[clap(
        short = 's',
        long = "snapshot-length",
        default_value_t = 96,
        conflicts_with = "infile"
    )]
    snapshot_length: u32,

    /// Read packet data from infile.
    #[clap(short = 'r', long = "read-file", conflicts_with = "interface")]
    infile: Option<String>,

    /// Packet filter in Wireshark display filter syntax. Merged with default for data packets.
    #[clap(short = 'Y', long = "display-filter", requires = "infile")]
    display_filter: Option<String>,

    /// Seconds with no activity to consider a new burst.
    #[clap(short = 't', long = "inactive-time", default_value_t = 1.0)]
    inactive_time: f64,

    /// Ignore ports when and create bursts based on IP addresses only.
    #[clap(short = 'p', long = "ignore-ports", conflicts_with = "wlan")]
    ignore_ports: bool,

    /// Write captured packets by tshark to a capture file.
    #[clap(short = 'w', long = "write-capture")]
    capture_outfile: Option<String>,

    /// Only display bursts with a minimum amount of bytes.
    #[clap(short = 'b', long = "min-bytes")]
    min_bytes: Option<u32>,

    /// Only display bursts with a maximum amount of bytes.
    #[clap(short = 'B', long = "max-bytes")]
    max_bytes: Option<u32>,

    /// Only display bursts with a minimum amount of packets/frames.
    #[clap(short = 'n', long = "min-packets")]
    min_packets: Option<u16>,

    /// Only display bursts with a maximum amount of packets/frames.
    #[clap(short = 'N', long = "max-packets")]
    max_packets: Option<u16>,

    /// Read 802.11 WLAN QoS data frames instead of IP packets.
    #[clap(short = 'I', long = "wlan")]
    wlan: bool,

    /// Disable estimating sizes of WLAN frames missed by the capture device.
    #[clap(short = 'E', long = "no-estimation", requires = "wlan")]
    no_estimation: bool,

    /// Maximum allowed deviation from the expected sequence number for WLAN frames.
    #[clap(
        short = 'M',
        long = "max-deviation",
        default_value_t = 200,
        requires = "wlan"
    )]
    max_deviation: u16,

    #[clap(value_delimiter=' ', hide(true), conflicts_with_all(["capture_filter", "display_filter"]))]
    positional_filter: Option<Vec<String>>,
}

fn tshark_args(args: Args) -> Vec<String> {
    let mut tshark_args = vec!["-l", "-q", "-n", "-T", "fields"];

    #[rustfmt::skip]
    tshark_args.extend(match args.wlan {
        false => vec![
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "data.len",
            "-e", "quic.length",
            "-e", "udp.length",
            "-e", "tcp.len",
            "-e", "udp.srcport",
            "-e", "tcp.srcport",
            "-e", "udp.dstport",
            "-e", "tcp.dstport",
        ],
        true => vec![
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "data.len",
            "-e", "wlan.seq",
        ],
    });

    let default_filter = match (&args.infile, &args.wlan) {
        (None, false) => String::from(
            "udp or (tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0))",
        ),
        (None, true) => String::from("wlan type data subtype qos-data"),
        (Some(_), false) => String::from("udp or (tcp and tcp.len > 0)"),
        (Some(_), true) => String::from("wlan and wlan.fc.type_subtype == 40"),
    };

    let filter = match args
        .capture_filter
        .or(args.display_filter)
        .or(args.positional_filter.map(|f| f.join(" ")))
    {
        Some(filter) => format!("({}) and ({})", default_filter, filter),
        None => default_filter,
    };

    let snapshot_length = args.snapshot_length.to_string();

    tshark_args.extend(match &args.infile {
        Some(infile) => vec!["-Y", &filter, "-r", infile],
        None => vec!["-s", &snapshot_length, "-f", &filter],
    });

    if let Some(interface) = &args.interface {
        tshark_args.extend(vec!["-i", interface]);
    }

    if let Some(capture_outfile) = &args.capture_outfile {
        tshark_args.extend(vec!["-w", capture_outfile, "-P"]);
    }

    tshark_args.into_iter().map(str::to_string).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = Args::parse();

    let output_tx = OutputWriter::new(
        args.min_bytes,
        args.max_bytes,
        args.min_packets,
        args.max_packets,
    )
    .start()
    .await;

    let opts = CommonOptions {
        tshark_args: tshark_args(args.clone()),
        inactive_time: args.inactive_time,
        output_tx,
    };

    match args.wlan {
        false => CaptureType::Ip {
            opts,
            ignore_ports: args.ignore_ports,
        },
        true => CaptureType::Wlan {
            opts,
            no_estimation: args.no_estimation,
            max_deviation: args.max_deviation,
        },
    }
    .run()
    .await?;

    Ok(())
}
