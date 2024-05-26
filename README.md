# BurstShark

BurstShark is a network traffic analysis tool that wraps around tshark to identify and analyze bursty application data traffic, such as adaptive streaming, in real-time or from pcap files. It captures application data packets and frames and records their sizes, creating bursts that happen within a small window of time. The output of the program consists of a line for each burst between two addresses and/or port. In the case of WLAN capture, such as when using monitor mode, MAC addresses will be displayed instead of IP addresses.

Each output line contains the following information:

* Burst counter (incremental)
* Completion time (s) of the burst relative to the program start
* Source IP or MAC address
* Source port (0 if no port)
* Destination IP or MAC address
* Destination port (0 if no port)
* Unix timestamp of the first packet in the burst
* Unix timestamp of the last packet in the burst
* Delay (s) between BurstShark reporting the burst and its last packet
* Number of packets in the burst
* Total size (in bytes) of the burst

## Usage
The full options of BurstShark can be seen below.

```
$ burstshark -h

BurstShark is a network traffic analysis tool that wraps around tshark to identify and analyze bursty application data traffic, such as adaptive streaming, in real-time or from pcap files.

Usage: burstshark [OPTIONS]

Options:
  -i, --interface <INTERFACE>
          Network interface to use for live capture
  -f, --capture-filter <CAPTURE_FILTER>
          Packet filter for live capture in libpcap filter syntax
  -s, --snapshot-length <SNAPLEN>
          Number of bytes to capture per packet during live capture [default: 96]
  -r, --read-file <INFILE>
          Read packet data from infile
  -Y, --display-filter <DISPLAY_FILTER>
          Packet filter in Wireshark display filter syntax
  -t, --burst_timeout <BURST_TIMEOUT>
          Seconds with no flow activity for a burst to be considered complete [default: 0.5]
  -a, --aggregate-ports
          Aggregate ports for flows with the same IP src/dst pair to a single flow
  -w, --write-pcap <PCAP_OUTFILE>
          Write raw packet data read by tshark to pcap_outfile
  -b, --min-bytes <MIN_BYTES>
          Only display bursts with a minimum size of min_bytes
  -B, --max-bytes <MAX_BYTES>
          Only display bursts with a maximum size of max_bytes
  -p, --min-packets <MIN_PACKETS>
          Only display bursts with a minimum amount of min_packets packets/frames
  -P, --max-packets <MAX_PACKETS>
          Only display bursts with a maximum amount of max_packets packets/frames
  -I, --wlan
          Read 802.11 WLAN QoS data frames instead of IP packets
  -E, --no-estimation
          Disable frame size estimation for missed WLAN frames
  -M, --max-deviation <MAX_DEVIATION>
          Maximum allowed deviation from the expected WLAN sequence number [default: 200]
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version
```
