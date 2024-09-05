# Network Traffic Analyzer
![Go Shark Logo - Cyberpunk Style](https://i.imgur.com/DOZ8lku.png)

This project provides a network traffic analyzer tool implemented in both Go and Python. The tool reads pcap files, analyzes network traffic, and detects various types of network activities, such as nmap scans, ARP poisoning, ICMP tunneling, and more. The output is provided in JSON format, containing detailed information about each detected packet.

## Repository

Find the Refernce for functions and filters i used:


- [Wire shark Lab Write up ](https://medium.com/@kumarishefu.4507/try-hack-me-wireshark-traffic-analysis-write-up-part-1-8fa705db0dae)
- [Wire shark Lab Write up part 2 ](https://medium.com/@kumarishefu.4507/try-hack-me-wireshark-traffic-analysis-write-up-part-2-11d299b504f3)


## Requirements

### Go Version

- [Go](https://golang.org/doc/install) (version 1.16 or higher)
- [GoPacket](https://pkg.go.dev/github.com/google/gopacket) package

### Python Version

- [Python](https://www.python.org/downloads/) (version 3.6 or higher)
- Required Python packages are listed in the `req.txt` file.

## Installation

### Go Version

1. **Install Go**: Download and install Go from the [official website](https://golang.org/doc/install).
2. **Clone this repository**: 
   ```bash
   git clone https://github.com/0xhatim/Network-Traffic-Analyzer.git
   cd Network-Traffic-Analyzer
   go get github.com/google/gopacket/pcap@v1.1.19
   ```
for python

pip install -r req.txt


running script 
use go run or 
go build -o network_operations network_operations.go

./network_operations --file path/to/your/file.pcap
or path and its read all dir
same for python


