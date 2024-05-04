use std::{
    collections::HashMap,
    error::Error,
    io::BufRead,
    net::IpAddr,
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
};

use macaddr::MacAddr;
use nix::sys::signal;

#[derive(Debug, Clone)]
pub struct Burst {
    pub completion_time: f64,
    pub src: String,
    pub dst: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub start: f64,
    pub end: f64,
    pub num_packets: u16,
    pub size: u32,
}

pub struct CommonOptions {
    pub tshark_args: Vec<String>,
    pub inactive_time: f64,
    pub tx: Sender<Burst>,
}

pub enum CaptureType {
    IPCapture {
        opts: CommonOptions,
        ignore_ports: bool,
    },
    WLANCapture {
        opts: CommonOptions,
        no_guess: bool,
        max_deviation: u16,
    },
}

impl CaptureType {
    pub fn run(&self) -> Result<(), Box<dyn Error>> {
        let opts = match self {
            CaptureType::IPCapture { opts, .. } | CaptureType::WLANCapture { opts, .. } => opts,
        };

        let mut tshark = Command::new("tshark")
            .args(&opts.tshark_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|err| format!("Failed to start tshark: {err}"))?;

        // Set up interrupt handler (ctrl-c)
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let tshark_pid = tshark.id() as i32;
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            let pid = nix::unistd::Pid::from_raw(tshark_pid);
            signal::kill(pid, signal::Signal::SIGINT).expect("Failed to send SIGINT to tshark");
        })?;

        let stdout = tshark.stdout.take().unwrap();
        let reader = std::io::BufReader::new(stdout);

        match self {
            CaptureType::IPCapture { ignore_ports, .. } => {
                let mut flows: HashMap<(IpAddr, IpAddr, Option<u16>, Option<u16>), IpFlow> =
                    HashMap::new();
                for line in reader.lines() {
                    let packet = match IpPacket::from_tshark(&line.unwrap()) {
                        Ok(packet) => packet,
                        Err(_) => continue,
                    };
                    let flow_key = if *ignore_ports {
                        (packet.src, packet.dst, None, None)
                    } else {
                        (
                            packet.src,
                            packet.dst,
                            Some(packet.src_port),
                            Some(packet.dst_port),
                        )
                    };
                    flows
                        .entry(flow_key)
                        .and_modify(|flow| flow.add_packet(&packet, &opts.tx, opts.inactive_time))
                        .or_insert_with(|| IpFlow::new(&packet, *ignore_ports));
                }
            }
            CaptureType::WLANCapture {
                no_guess,
                max_deviation,
                ..
            } => {
                let mut flows: HashMap<(MacAddr, MacAddr), WlanFlow> = HashMap::new();
                for line in reader.lines() {
                    let packet = match WlanPacket::from_tshark(&line.unwrap()) {
                        Ok(packet) => packet,
                        Err(_) => continue,
                    };
                    flows
                        .entry((packet.src, packet.dst))
                        .and_modify(|flow| flow.add_packet(&packet, &opts.tx, opts.inactive_time))
                        .or_insert_with(|| WlanFlow::new(&packet, *no_guess, *max_deviation));
                }
            }
        }

        tshark.wait()?;
        Ok(())
    }
}

struct IpPacket {
    time: f64,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    data_len: u32,
}

struct WlanPacket {
    time: f64,
    src: MacAddr,
    dst: MacAddr,
    data_len: u32,
    seq_number: u16,
}

struct IpFlow {
    ignore_ports: bool,
    current_burst: Burst,
}

struct WlanFlow {
    current_burst: Burst,
    expected_seq_number: u16,
    last_packet_len: u32,
    no_guess: bool,
    max_deviation: u16,
}

impl IpPacket {
    fn from_tshark(line: &str) -> Result<Self, Box<dyn Error>> {
        let mut fields = line.split_whitespace();
        Ok(IpPacket {
            time: fields.next().unwrap().parse::<f64>()?,
            src: IpAddr::from_str(fields.next().unwrap())?,
            dst: IpAddr::from_str(fields.next().unwrap())?,
            src_port: fields.next().unwrap().parse::<u16>()?,
            dst_port: fields.next().unwrap().parse::<u16>()?,
            data_len: fields.next().unwrap().parse::<u32>()?,
        })
    }
}

impl WlanPacket {
    fn from_tshark(line: &str) -> Result<Self, Box<dyn Error>> {
        let mut fields = line.split_whitespace();
        Ok(WlanPacket {
            time: fields.next().unwrap().parse::<f64>()?,
            src: MacAddr::from_str(fields.next().unwrap())?,
            dst: MacAddr::from_str(fields.next().unwrap())?,
            data_len: fields.next().unwrap().parse::<u32>()?,
            seq_number: fields.next().unwrap().parse::<u16>()?,
        })
    }
}

impl IpFlow {
    fn new(p: &IpPacket, ignore_ports: bool) -> Self {
        IpFlow {
            ignore_ports,
            current_burst: Burst::from_ip_packet(p, ignore_ports),
        }
    }

    fn add_packet(&mut self, p: &IpPacket, tx: &Sender<Burst>, inactive_time: f64) {
        if p.time - self.current_burst.end > inactive_time {
            self.current_burst.completion_time = p.time;
            tx.send(self.current_burst.clone()).unwrap();
            self.current_burst = Burst::from_ip_packet(p, self.ignore_ports);
        } else {
            self.current_burst.end = p.time;
            self.current_burst.num_packets += 1;
            self.current_burst.size += p.data_len;
        }
    }
}

impl WlanFlow {
    fn new(p: &WlanPacket, no_guess: bool, max_deviation: u16) -> Self {
        WlanFlow {
            current_burst: Burst::from_wlan_packet(p),
            expected_seq_number: p.seq_number,
            last_packet_len: p.data_len,
            no_guess,
            max_deviation,
        }
    }

    fn add_packet(&mut self, p: &WlanPacket, tx: &Sender<Burst>, inactive_time: f64) {
        if p.time - self.current_burst.end > inactive_time {
            self.current_burst.completion_time = p.time;
            tx.send(self.current_burst.clone()).unwrap();
            self.current_burst = Burst::from_wlan_packet(p);

            // Accept sequence number of packet after the inactive time.
            self.expected_seq_number = (p.seq_number + 1) & 4095;
            self.last_packet_len = p.data_len;
        } else {
            // Packet sequence number is what we expect.
            if p.seq_number == self.expected_seq_number {
                self.expected_seq_number = (p.seq_number + 1) & 4095;
                self.last_packet_len = p.data_len;
                self.current_burst.end = p.time;
                self.current_burst.num_packets += 1;
                self.current_burst.size += p.data_len;
                return;
            }

            // Packet sequence number not what we expect.
            let diff = (p.seq_number as i16 - self.expected_seq_number as i16) & 4095;
            let signed_diff = if diff <= 2048 { diff } else { diff - 4096 };

            // We already added this packet, but it is probably being retransmitted.
            // Note: not enough to filter on the retransmission bit as the first frame might be lost.
            if -(self.max_deviation as i16) < signed_diff && signed_diff < 0 {
                self.current_burst.end = p.time;
                return;
            }

            // The packet has a sequence number that is further along than what we expect.
            // Monitor mode device might have missed frames.
            if 0 < signed_diff && signed_diff < self.max_deviation as i16 {
                if !self.no_guess {
                    // Guess the lengths of the lost frames
                    let guess = (self.last_packet_len + p.data_len) / 2;
                    self.current_burst.num_packets += diff as u16;
                    self.current_burst.size += guess * diff as u32;
                } else {
                    // Accept only this
                    self.current_burst.num_packets += 1;
                    self.current_burst.size += p.data_len;
                }
                // Bring the expected sequence number in line with the packet.
                self.expected_seq_number = (p.seq_number + 1) & 4095;
                self.last_packet_len = p.data_len;
                self.current_burst.end = p.time;
            } else {
                // In case of a larger deviation, might be a single outlier, go to next expected.
                self.expected_seq_number = (self.expected_seq_number + 1) & 4095;
            }
        }
    }
}

impl Burst {
    fn from_ip_packet(p: &IpPacket, ignore_ports: bool) -> Self {
        let (src_port, dst_port) = if ignore_ports {
            (None, None)
        } else {
            (Some(p.src_port), Some(p.dst_port))
        };
        Burst {
            completion_time: p.time,
            src: p.src.to_string(),
            dst: p.dst.to_string(),
            src_port,
            dst_port,
            start: p.time,
            end: p.time,
            num_packets: 1,
            size: p.data_len,
        }
    }
    fn from_wlan_packet(p: &WlanPacket) -> Self {
        Burst {
            completion_time: p.time,
            src: p.src.to_string(),
            dst: p.dst.to_string(),
            src_port: None,
            dst_port: None,
            start: p.time,
            end: p.time,
            num_packets: 1,
            size: p.data_len,
        }
    }
}
