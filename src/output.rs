use std::{
    error::Error,
    fs::File,
    io::Write,
    sync::mpsc,
    thread,
};

use crate::capture::Burst;

pub struct OutputWriter {
    outfile: Option<String>,
    suppress: bool,
    min_bytes: Option<u32>,
    min_packets: Option<u16>,
    handle: Option<thread::JoinHandle<()>>,
}

impl OutputWriter {
    pub fn new(outfile: Option<String>, suppress: bool, min_bytes: Option<u32>, min_packets: Option<u16>) -> Self {
        OutputWriter {
            outfile: outfile,
            suppress: suppress,
            min_bytes: min_bytes,
            min_packets: min_packets,
            handle: None,
        }
    }

    pub fn start(&mut self) -> Result<mpsc::Sender<Burst>, Box<dyn Error>> {
        let (tx, rx) = mpsc::channel();

        // Create new file if outfile is supplied.
        let mut file = match &self.outfile {
            Some(filename) => Some(File::create(filename)?),
            None => None,
        };

        let suppress = self.suppress;
        let min_bytes = self.min_bytes;
        let min_packets = self.min_packets;

        self.handle = Some(thread::spawn(move || {
            let mut count = 1;

            loop {
                let burst: Burst = match rx.recv() {
                    Ok(burst) => burst,
                    
                    // Done when channel dropped.
                    Err(_) => break,
                };

                if (min_bytes.map_or(false, |min| min > burst.size)) 
                    || (min_packets.map_or(false, |min| min > burst.num_packets))
                {
                    continue;
                }

                let line = format!(
                    "{}\t{}\t{}\t{:13.9}\t{:13.9}\t{}\t{}",
                    count,
                    burst.src,
                    burst.dst,
                    burst.start,
                    burst.end,
                    burst.num_packets,
                    burst.size,
                );  
        
                if !suppress {
                    println!("{}", line);
                }
    
                if let Some(ref mut file) = file {
                    writeln!(file, "{}", line).expect("Error writing to file");
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
