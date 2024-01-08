use clap::{Parser, ValueEnum};

mod capture;
mod output;

use capture::{CaptureType, CommonOptions};
use output::OutputWriter;

#[derive(Parser, Clone, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Protocol to run BurstShark on.
    #[clap(value_enum, short = 'p', long = "protocol", default_value_t = Protocol::Ip)]
    protocol: Protocol,

    /// Read packet data from infile.
    #[clap(short = 'r', long = "read-file")]
    infile: Option<String>,
    
    /// Network interface to use for live capture. First non-loopback interface if no interface or file supplied.
    #[clap(short = 'i', long = "interface")]
    interface: Option<String>,
    
    /// Seconds with no activity to consider a new burst.
    #[clap(short = 't', long = "inactive-time", default_value_t = 1.0)]
    inactive_time: f64,

    /// Ignore ports when using IP protocol and create bursts based on IP addresses only.
    #[clap(short = 'I', long = "ignore-ports")]
    ignore_ports: bool,

    /// Capture filter using BPF syntax. Merged with default that filters for application data packets.
    #[clap(short = 'f', long = "capture-filter")]
    capture_filter: Option<String>,

    /// Display filter. Merged with default that filters for application data packets.
    #[clap(short = 'Y', long = "display-filter")]
    display_filter: Option<String>,

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

    /// Only display bursts that started after time relative to the first packet/frame.
    #[clap(short = 'A', long = "start-time")]
    start_time: Option<f64>,

    /// Disable guessing sizes of WLAN data frames missed by the monitor mode device.
    #[clap(short = 'G', long = "no-guess")]
    no_guess: bool,

    /// Maximum allowed deviation from the expected sequence number for WLAN frames.
    #[clap(short = 'M', long = "max-deviation", default_value_t = 50)]
    max_deviation: u16,
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
    /// Run BurstShark on TCP and UDP application data.
    Ip,

    /// Run BurstShark on IEEE 802.11 data frames, typically using monitor mode.
    Wlan,
}


fn tshark_args(args: Args) -> Vec<String> {
    let mut capture_filter = match args.protocol {
        Protocol::Ip => String::from("udp or tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"),
        Protocol::Wlan => String::from("wlan type data subtype qos-data"),
    };

    if let Some(filter) = args.capture_filter {
        capture_filter = format!("({}) and ({})", capture_filter, filter);
    }

    let mut display_filter = match args.protocol {
        Protocol::Ip => String::from("udp || (tcp && tcp.len > 0)"),
        Protocol::Wlan => String::from("wlan && wlan.fc.type_subtype == 40"),
    };

    if let Some(filter) = args.display_filter {
        display_filter = format!("({}) && ({})", display_filter, filter);
    }

    let mut tshark_args = match (&args.infile, &args.interface, &args.capture_outfile) {
        (Some(infile), _, _) => vec![
            "-r", infile, 
            "-Y", &display_filter,
            "-Q",
        ],
        (_, Some(interface), Some(capture_outfile)) => vec![
            "-n",
            "-i", interface,
            "-f", &capture_filter,
            "-w", capture_outfile,
            "-P",
            "-Q",
        ],
        (_, Some(interface), _) => vec![
            "-n",
            "-i", interface,
            "-f", &capture_filter,
            "-Q",
        ],
        (_, _, Some(capture_outfile)) => vec![
            "-n",
            "-f", &capture_filter,
            "-w", capture_outfile,
            "-P",
            "-Q",
        ],
        _ => vec![
            "-n",
            "-f", &capture_filter,
            "-Q",
        ],
    };

    let time_format_field = match args.time_format {
        TimeFormat::Relative => "frame.time_relative",
        TimeFormat::Epoch => "frame.time_epoch",
    };

    tshark_args.extend(match args.protocol {
        Protocol::Ip => vec![
            "-T", "fields",
            "-e", time_format_field,
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
            "-T", "fields",
            "-e", time_format_field,
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

    let mut output_writer = OutputWriter::new(
        args.bursts_outfile.clone(),
        args.suppress,
        args.min_bytes,
        args.max_bytes,
        args.min_packets,
        args.max_packets,
        args.start_time,
    );

    let tx = match output_writer.start() {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Error starting output writer: {}", e);
            return
        },
    };

    let opts = CommonOptions {
        tshark_args: tshark_args(args.clone()),
        inactive_time: args.inactive_time,
        tx
    };

    let capture_result = match args.protocol {
        Protocol::Ip => CaptureType::IPCapture { opts, ignore_ports: args.ignore_ports }.run(),
        Protocol::Wlan => CaptureType::WLANCapture { opts, no_guess: args.no_guess, max_deviation: args.max_deviation }.run(),
    };

    output_writer.stop();

    if let Err(e) = capture_result {
        eprintln!("Error running capture: {}", e);
    }
}
