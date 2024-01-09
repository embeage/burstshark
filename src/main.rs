use clap::{Parser, ValueEnum};

mod capture;
mod output;

use capture::{CaptureType, CommonOptions};
use output::OutputWriter;

#[derive(Parser, Clone, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Network interface to use for live capture. First non-loopback interface if no interface or file supplied.
    #[clap(short = 'i', long = "interface")]
    interface: Option<String>,

    /// Read packet data from infile.
    #[clap(short = 'r', long = "read-file", conflicts_with = "interface")]
    infile: Option<String>,

    /// Packet filter in libpcap filter syntax. Merged with default for data packets.
    #[clap(short = 'f', long = "capture-filter", conflicts_with = "infile")]
    capture_filter: Option<String>,

    /// Packet filter in Wireshark display filter syntax. Merged with default for data packets.
    #[clap(short = 'Y', long = "display-filter", requires = "infile")]
    display_filter: Option<String>,
    
    /// Seconds with no activity to consider a new burst.
    #[clap(short = 't', long = "inactive-time", default_value_t = 1.0)]
    inactive_time: f64,

    /// Ignore ports when and create bursts based on IP addresses only.
    #[clap(short = 'p', long = "ignore-ports", conflicts_with = "monitor_mode")]
    ignore_ports: bool,

    /// Write captured packets by tshark to a capture file.
    #[clap(short = 'w', long = "write-capture")]
    capture_outfile: Option<String>,

    /// Write output from BurstShark to a file.
    #[clap(short = 'W', long = "write-bursts")]
    bursts_outfile: Option<String>,

    /// Don't display bursts on the standard output.
    #[clap(short = 'q', long = "suppress")]
    suppress: bool,

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

    /// Which time format to use for output.
    #[clap(value_enum, short = 'T', long = "time-format", default_value_t = TimeFormat::Relative)]
    time_format: TimeFormat,

    /// Capture 802.11 WLAN frames instead of IP packets.
    #[clap(short = 'I', long = "monitor-mode")]
    monitor_mode: bool,

    /// Disable guessing sizes of WLAN data frames missed by the monitor mode device.
    #[clap(short = 'G', long = "no-guess", requires = "monitor_mode")]
    no_guess: bool,

    /// Maximum allowed deviation from the expected sequence number for WLAN frames.
    #[clap(short = 'M', long = "max-deviation", default_value_t = 50, requires = "monitor_mode")]
    max_deviation: u16,

    #[clap(value_delimiter=' ', hide(true), conflicts_with_all(["capture_filter", "display_filter"]))]
    positional_filter: Option<Vec<String>>,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum TimeFormat {
    /// Time relative to the first packet/frame.
    Relative,

    /// Time in seconds since the UNIX epoch.
    Epoch,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum Protocol {
    Ip,
    Wlan,
}

fn tshark_args(protocol: &Protocol, args: Args) -> Vec<String> {
    let default_filter = match (&args.infile, &args.monitor_mode) {
        (None, false) => String::from("udp or (tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0))"),
        (None, true) => String::from("wlan type data subtype qos-data"),
        (Some(_), false) => String::from("udp or (tcp and tcp.len > 0)"),
        (Some(_), true) => String::from("wlan and wlan.fc.type_subtype == 40"),
    };

    let optional_filter = args.capture_filter.or(args.display_filter);
    let supplied_filter = optional_filter.or(args.positional_filter.map(|f| f.join(" ")));

    let filter = match supplied_filter{
        Some(filter) => format!("({}) and ({})", default_filter, filter),
        None => default_filter,
    };

    let mut tshark_args = match &args.infile {
        Some(infile) => vec![
            "-r", infile, 
            "-Y", &filter,
        ],
        None => vec![
            "-n",
            "-f", &filter,
        ],
    };

    if let Some(interface) = &args.interface {
        tshark_args.extend(vec!["-i", interface]);
    }

    if let Some(capture_outfile) = &args.capture_outfile {
        tshark_args.extend(vec![
            "-w", capture_outfile,
            "-P",
        ]);
    }

    tshark_args.extend(vec![
        "-Q",
        "-l",
        "-T", "fields",
        "-e", match args.time_format {
            TimeFormat::Relative => "frame.time_relative",
            TimeFormat::Epoch => "frame.time_epoch",
        },
    ]);

    tshark_args.extend(match protocol {
        Protocol::Ip => vec![
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "udp.srcport",
            "-e", "tcp.srcport",
            "-e", "udp.dstport",
            "-e", "tcp.dstport",
            "-e", "data.len",
            "-e", "udp.length",
            "-e", "tcp.len",
        ],
        Protocol::Wlan => vec![
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "data.len",
            "-e", "wlan.seq",
        ],
    });

    tshark_args.into_iter().map(str::to_string).collect()
}

fn main() {
    let args: Args = Args::parse();
    let protocol = match args.monitor_mode {
        true => Protocol::Wlan,
        false => Protocol::Ip,
    };

    let mut output_writer = OutputWriter::new(
        args.bursts_outfile.clone(),
        args.suppress,
        args.min_bytes,
        args.max_bytes,
        args.min_packets,
        args.max_packets,
    );

    let tx = match output_writer.start() {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Error starting output writer: {}", e);
            return
        },
    };

    let opts = CommonOptions {
        tshark_args: tshark_args(&protocol, args.clone()),
        inactive_time: args.inactive_time,
        tx
    };

    let capture_result = match protocol {
        Protocol::Ip => CaptureType::IPCapture { opts, ignore_ports: args.ignore_ports }.run(),
        Protocol::Wlan => CaptureType::WLANCapture { opts, no_guess: args.no_guess, max_deviation: args.max_deviation }.run(),
    };

    output_writer.stop();

    if let Err(e) = capture_result {
        eprintln!("Error running capture: {}", e);
    }
}
