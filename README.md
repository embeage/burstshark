# BurstShark

**Note: README not yet complete**

BurstShark is a network traffic analysis tool that wraps around tshark to identify and analyze bursty application data traffic, such as adaptive streaming, in real-time or from pcap files. It captures application data packets and frames and records their sizes, creating bursts that happen within a small window of time. The output of the program consists of a line for each burst between two addresses and/or port. In the case of WLAN capture, such as when using monitor mode, MAC addresses will be displayed instead of IP addresses.

Each output line contains the following information:

* Burst counter (incremental)
* Completion time of the burst (relative or epoch time)
* Source IP or MAC address
* Source port (or empty no port)
* Destination IP or MAC address
* Destination port (or empty if no port)
* Start time of the burst (relative or epoch time)
* End time of the burst (relative or epoch time)
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
          Network interface to use for live capture. First non-loopback interface if no interface or file supplied
  -r, --read-file <INFILE>
          Read packet data from infile
  -f, --capture-filter <CAPTURE_FILTER>
          Packet filter in libpcap filter syntax. Merged with default for data packets
  -Y, --display-filter <DISPLAY_FILTER>
          Packet filter in Wireshark display filter syntax. Merged with default for data packets
  -t, --inactive-time <INACTIVE_TIME>
          Seconds with no activity to consider a new burst [default: 1]
  -p, --ignore-ports
          Ignore ports when and create bursts based on IP addresses only
  -w, --write-capture <CAPTURE_OUTFILE>
          Write captured packets by tshark to a capture file
  -W, --write-bursts <BURSTS_OUTFILE>
          Write output from BurstShark to a file
  -q, --suppress
          Don't display bursts on the standard output
  -b, --min-bytes <MIN_BYTES>
          Only display bursts with a minimum amount of bytes
  -B, --max-bytes <MAX_BYTES>
          Only display bursts with a maximum amount of bytes
  -n, --min-packets <MIN_PACKETS>
          Only display bursts with a minimum amount of packets/frames
  -N, --max-packets <MAX_PACKETS>
          Only display bursts with a maximum amount of packets/frames
  -T, --time-format <TIME_FORMAT>
          Which time format to use for output [default: relative] [possible values: relative, epoch]
  -I, --monitor-mode
          Capture 802.11 WLAN frames instead of IP packets
  -G, --no-guess
          Disable guessing sizes of WLAN data frames missed by the monitor mode device
  -M, --max-deviation <MAX_DEVIATION>
          Maximum allowed deviation from the expected sequence number for WLAN frames [default: 50]
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version
```
