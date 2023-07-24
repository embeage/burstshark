# BurstShark

**Note: README not yet complete**

BurstShark is a network traffic analysis tool that wraps around tshark to identify and analyze bursty application data traffic, such as adaptive streaming, in real-time or from pcap files. It captures application data packets and frames and records their sizes, creating bursts that happen within a small window of time. The output of the program consists of a line for each burst between two addresses, which could be IP or MAC depending on the capture type. In the case of WLAN capture, such as when using monitor mode, MAC addresses will be used instead of IP addresses.

Each output line contains the following information:

* Burst counter (incremental)
* Source IP or MAC address
* Destination IP or MAC address
* Start time of the burst (timestamp)
* End time of the burst (timestamp)
* Number of packets in the burst
* Total size (in bytes) of the burst

## Usage
The full options of BurstShark can be seen below.

```
$ burstshark -h

BurstShark is a network traffic analysis tool that wraps around tshark to identify and analyze bursty application data traffic, such as adaptive streaming, in real-time or from pcap files.

Usage: burstshark [OPTIONS]

Options:
  -p, --protocol <PROTOCOL> Protocol to run BurstShark on [default: tcp] [possible values: tcp, ip, wlan]
  -r, --read-file <INFILE> Read packet data from infile
  -i, --interface <INTERFACE> Network interface to use for live capture. First non-loopback interface if no interface or file supplied
  -t, --inactive-time <INACTIVE_TIME> Seconds with no activity to consider a new burst [default: 1]
  -s, --src <SRC>... One or more space separated source addresses to filter on
  -d, --dst <DST>... One or more space separated destination addresses to filter on
  -w, --write-capture <CAPTURE_OUTFILE> Write captured packets by tshark to a capture file
  -W, --write-bursts <BURSTS_OUTFILE> Write output from BurstShark to a file
  -q, --suppress Don't show any bursts on the standard output
  -b, --min-bytes <MIN_BYTES> Only show bursts with a minimum amount of bytes
  -B, --max-bytes <MAX_BYTES> Only show bursts with a maximum amount of bytes
  -P, --min-packets <MIN_PACKETS> Only show bursts with a minimum amount of packets/frames
  -A, --start-time <START_TIME> Only show bursts that started after time relative to the first packet/frame
  -G, --no-guess Disable guessing sizes of WLAN data frames missed by the monitor mode device
  -M, --max-deviation <MAX_DEVIATION> Maximum allowed deviation from the expected sequence number for WLAN frames [default: 50]
  -h, --help Print help (see more with '--help')
```
