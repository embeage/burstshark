use clap::{Parser, ValueEnum};

mod capture;
mod output;

use capture::{CaptureType, CommonOptions};
use output::OutputWriter;

#[derive(Parser, Clone, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Protocol to run BurstShark on.
    #[clap(value_enum, short = 'p', long = "protocol", default_value = "tcp")]
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
    
    /// One or more space separated source addresses to filter on.
    #[clap(short = 's', long = "src", value_parser, num_args = 1.., value_delimiter = ' ')]
    src: Option<Vec<String>>,
    
    /// One or more space separated destination addresses to filter on.
    #[clap(short = 'd', long = "dst", value_parser, num_args = 1.., value_delimiter = ' ')]
    dst: Option<Vec<String>>,
    
    /// Write captured packets by tshark to a capture file.
    #[clap(short = 'w', long = "write-capture")]
    capture_outfile: Option<String>,

    /// Write output from BurstShark to a file.
    #[clap(short = 'W', long = "write-bursts")]
    bursts_outfile: Option<String>,

    /// Don't show any bursts on the standard output.
    #[clap(short = 'q', long = "suppress")]
    suppress: bool,

    /// Only show bursts with a minimum amount of bytes.
    #[clap(short = 'B', long = "min-bytes")]
    min_bytes: Option<u32>,

    /// Only show bursts with a minimum amount of packets/frames.
    #[clap(short = 'P', long = "min-packets")]
    min_packets: Option<u16>,

    /// Disable guessing sizes of WLAN data frames missed by the monitor mode device.
    #[clap(short = 'G', long = "no-guess")]
    no_guess: bool,

    /// Maximum allowed deviation from the expected sequence number for WLAN frames.
    #[clap(short = 'M', long = "max-deviation", default_value_t = 50)]
    max_deviation: u16,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum Protocol {
    /// Run BurstShark on TCP application data segments.
    Tcp,

    /// Run BurstShark on IPv4 or IPv6 packets.
    Ip,

    /// Run BurstShark on IEEE 802.11 data frames, typically using monitor mode.
    Wlan,
}


fn tshark_args(args: Args) -> Vec<String> {
    let capture_filter = capture_filter(&args.protocol, &args.src, &args.dst);
    let display_filter = display_filter(&args.protocol, &args.src, &args.dst);

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

    tshark_args.extend(match args.protocol {
        Protocol::Tcp => vec![
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.len",
        ],
        Protocol::Ip => vec![
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.len",
        ],
        Protocol::Wlan => vec![
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "data.len",
            "-e", "wlan.seq",
        ],
    });

    tshark_args.into_iter().map(str::to_string).collect()
}

fn capture_filter(protocol: &Protocol, src: &Option<Vec<String>>, dst: &Option<Vec<String>>) -> String {
    match protocol {
        Protocol::Tcp => {
            let default = "tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
            extend_filter(
                &extend_filter(
                    default, 
                    "ip src", 
                    src), 
                "ip dst",
                dst
            )
        },
        Protocol::Ip => {    
            let default = "ip";
            extend_filter(
                &extend_filter(
                    default, 
                    "ip src", 
                    src), 
                "ip dst",
                dst
            )
        },
        Protocol::Wlan => {    
            let default = "wlan type data subtype qos-data";
            extend_filter(
                &extend_filter(
                    default, 
                    "wlan src", 
                    src), 
                "wlan dst",
                dst
            )
        },
    }
}

fn display_filter(protocol: &Protocol, src: &Option<Vec<String>>, dst: &Option<Vec<String>>) -> String {
    match protocol {
        Protocol::Tcp => {
            let default = "tcp and tcp.len > 0";
            extend_filter(
                &extend_filter(
                    default, 
                    "ip.src ==", 
                    src), 
                "ip.dst ==",
                dst
            )
        },
        Protocol::Ip => {    
            let default = "ip";
            extend_filter(
                &extend_filter(
                    default, 
                    "ip.src ==", 
                    src), 
                "ip.dst ==",
                dst
            )
        },
        Protocol::Wlan => {    
            let default = "wlan and wlan.fc.type_subtype == 40";
            extend_filter(
                &extend_filter(
                    default, 
                    "wlan.sa ==", 
                    src), 
                "wlan.da ==",
                dst
            )
        },
    }
}

fn extend_filter(filter: &str, field: &str, addresses: &Option<Vec<String>>) -> String {
    match addresses {
        Some(adr) => {
            let extended: Vec<String> = adr
                .iter()
                .map(|address| format!("{} {}", field, address))
                .collect();

            format!("({}) and ({})", filter, extended.join(" or "))
        }
        None => filter.to_string(),
    }
}

fn main() {
    let args: Args = Args::parse();

    let mut output_writer = OutputWriter::new(
        args.bursts_outfile.clone(),
        args.suppress,
        args.min_bytes,
        args.min_packets,
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
        tx: tx
    };

    let capture_result = match args.protocol {
        Protocol::Tcp | Protocol::Ip => CaptureType::IPCapture { opts }.run(),
        Protocol::Wlan => CaptureType::WLANCapture { opts, no_guess: args.no_guess, max_deviation: args.max_deviation }.run(),
    };

    output_writer.stop();

    if let Err(e) = capture_result {
        eprintln!("Error running capture: {}", e);
    }
}
