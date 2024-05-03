use std::{
    error::Error,
    fmt::Write as FmtWrite,
    fs::File,
    io::{BufWriter, Write},
    sync::mpsc,
    thread,
};

use crate::capture::Burst;

pub struct OutputWriter {
    outfile: Option<String>,
    suppress: bool,
    min_bytes: Option<u32>,
    max_bytes: Option<u32>,
    min_packets: Option<u16>,
    max_packets: Option<u16>,
    handle: Option<thread::JoinHandle<()>>,
}

impl OutputWriter {
    pub fn new(
        outfile: Option<String>,
        suppress: bool,
        min_bytes: Option<u32>,
        max_bytes: Option<u32>,
        min_packets: Option<u16>,
        max_packets: Option<u16>,
    ) -> Self {
        OutputWriter {
            outfile,
            suppress,
            min_bytes,
            max_bytes,
            min_packets,
            max_packets,
            handle: None,
        }
    }

    pub fn start(&mut self) -> Result<mpsc::Sender<Burst>, Box<dyn Error>> {
        let (tx, rx) = mpsc::channel();

        let file = match &self.outfile {
            Some(filename) => Some(File::create(filename)?),
            None => None,
        };

        let suppress = self.suppress;
        let min_bytes = self.min_bytes;
        let max_bytes = self.max_bytes;
        let min_packets = self.min_packets;
        let max_packets = self.max_packets;

        self.handle = Some(thread::spawn(move || {
            let mut line = String::with_capacity(256);
            let mut count = 1;
            let mut buffer = match file {
                Some(file) => Some(BufWriter::new(file)),
                None => None,
            };

            loop {
                let burst: Burst = match rx.recv() {
                    Ok(burst) => burst,

                    // Done when channel dropped.
                    Err(_) => break,
                };

                if (min_bytes.map_or(false, |min| min >= burst.size))
                    || (max_bytes.map_or(false, |max| max <= burst.size))
                    || (min_packets.map_or(false, |min| min >= burst.num_packets))
                    || (max_packets.map_or(false, |max| max <= burst.num_packets))
                {
                    continue;
                }

                line.clear();
                write!(
                    &mut line,
                    "{:5} {:13.9} {:15} {:6} {:15} {:5} {:13.9} {:13.9} {:4} {}",
                    count,
                    burst.completion_time,
                    burst.src,
                    burst.src_port.map_or("".to_string(), |p| p.to_string()),
                    burst.dst,
                    burst.dst_port.map_or("".to_string(), |p| p.to_string()),
                    burst.start,
                    burst.end,
                    burst.num_packets,
                    burst.size,
                )
                .expect("Error writing to line");

                if !suppress {
                    println!("{}", line);
                }

                if let Some(buffer) = &mut buffer {
                    writeln!(buffer, "{}", line).expect("Error writing to file");
                }

                count += 1;
            }
        }));

        Ok(tx)
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}
