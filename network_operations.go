package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	PacketNumber     int      `json:"packet_number"`
	Timestamp        string   `json:"timestamp"`
	Protocols        []string `json:"protocols"`
	SrcIP            string   `json:"src_ip"`
	DstIP            string   `json:"dst_ip"`
	SrcPort          string   `json:"src_port"`
	DstPort          string   `json:"dst_port"`
	DetectionDetails []string `json:"detection_details"`
}

type BlueTeamTrafficAnalyzer struct {
	FilePath string
}

func (analyzer *BlueTeamTrafficAnalyzer) AnalyzePackets(handle *pcap.Handle) ([]PacketInfo, error) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packetReports []PacketInfo

	// Counters and data structures for detections
	nmapScanDetected := make(map[string]int)
	arpPoisoningDetected := make(map[string]string)
	icmpTunnelDetected := 0
	dnsTunnelDetected := 0
	anomalyDetected := make(map[string]int)

	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		packetInfo := PacketInfo{
			PacketNumber:     packetCount,
			Timestamp:        packet.Metadata().Timestamp.Format(time.RFC3339),
			Protocols:        []string{},
			DetectionDetails: []string{},
		}

		// Analyze Ethernet Layer
		if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
			eth := ethernetLayer.(*layers.Ethernet)
			packetInfo.SrcIP = eth.SrcMAC.String()
			packetInfo.DstIP = eth.DstMAC.String()
		}

		// Analyze IP Layer
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			packetInfo.SrcIP = ip.SrcIP.String()
			packetInfo.DstIP = ip.DstIP.String()

			// Anomaly Detection
			analyzer.detectAnomalies(ip, anomalyDetected, &packetInfo)
		}

		// Analyze TCP Layer
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			analyzer.detectNmapScans(tcp, nmapScanDetected, &packetInfo)
			packetInfo.Protocols = append(packetInfo.Protocols, "TCP")
		}

		// Analyze UDP Layer
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			analyzer.detectUdpScans(udp, nmapScanDetected, &packetInfo)
			packetInfo.Protocols = append(packetInfo.Protocols, "UDP")
		}

		// Analyze ARP Layer
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			analyzer.detectArpPoisoning(arp, arpPoisoningDetected, &packetInfo)
			packetInfo.Protocols = append(packetInfo.Protocols, "ARP")
		}

		// Analyze ICMP Layer
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			icmpTunnelDetected += analyzer.detectIcmpTunneling(icmp, &packetInfo)
			packetInfo.Protocols = append(packetInfo.Protocols, "ICMP")
		}

		// DNS Tunneling Detection Placeholder
		// The DNS layer in GoPacket is more complex and might require additional parsing.

		// If any detections were found, add the packet report
		if len(packetInfo.DetectionDetails) > 0 {
			packetReports = append(packetReports, packetInfo)
		}
	}

	analyzer.printResults(nmapScanDetected, arpPoisoningDetected, icmpTunnelDetected, dnsTunnelDetected, anomalyDetected)
	return packetReports, nil
}

func (analyzer *BlueTeamTrafficAnalyzer) detectNmapScans(tcp *layers.TCP, nmapScanDetected map[string]int, packetInfo *PacketInfo) {
	if tcp.SYN && !tcp.ACK && tcp.Window > 1024 {
		nmapScanDetected["tcp_connect"]++
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, "TCP connect scan detected: SYN flag with window size > 1024")
	} else if tcp.SYN && !tcp.ACK && tcp.Window <= 1024 {
		nmapScanDetected["syn"]++
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, "SYN scan detected: SYN flag with window size <= 1024")
	} else if tcp.FIN && tcp.PSH && tcp.URG {
		nmapScanDetected["xmas"]++
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, "XMAS scan detected: TCP flags indicating XMAS scan")
	} else if !tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST {
		nmapScanDetected["null"]++
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, "NULL scan detected: No TCP flags set")
	} else if tcp.FIN && !tcp.SYN && !tcp.ACK {
		nmapScanDetected["fin"]++
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, "FIN scan detected: Only FIN flag set")
	}
}

func (analyzer *BlueTeamTrafficAnalyzer) detectUdpScans(udp *layers.UDP, nmapScanDetected map[string]int, packetInfo *PacketInfo) {
	if udp.Length <= 8 {
		nmapScanDetected["udp"]++
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, "UDP scan detected: Packet length <= 8")
	}
}

func (analyzer *BlueTeamTrafficAnalyzer) detectArpPoisoning(arp *layers.ARP, arpPoisoningDetected map[string]string, packetInfo *PacketInfo) {
	if arp.Operation == layers.ARPReply {
		// Convert byte slices to strings
		ip := string(arp.SourceProtAddress)
		mac := string(arp.SourceHwAddress)
		if oldMac, found := arpPoisoningDetected[ip]; found && oldMac != mac {
			detail := fmt.Sprintf("ARP poisoning detected: IP %s has multiple MAC addresses.", ip)
			packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, detail)
		}
		arpPoisoningDetected[ip] = mac
	}
}

func (analyzer *BlueTeamTrafficAnalyzer) detectIcmpTunneling(icmp *layers.ICMPv4, packetInfo *PacketInfo) int {
	if len(icmp.Payload) > 64 {
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, "Potential ICMP tunneling detected.")
		return 1
	}
	return 0
}

func (analyzer *BlueTeamTrafficAnalyzer) detectAnomalies(ip *layers.IPv4, anomalyDetected map[string]int, packetInfo *PacketInfo) {
	anomalyDetected[ip.SrcIP.String()]++
	if anomalyDetected[ip.SrcIP.String()] > 100 {
		detail := fmt.Sprintf("Anomalous traffic volume detected from IP %s", ip.SrcIP.String())
		packetInfo.DetectionDetails = append(packetInfo.DetectionDetails, detail)
	}
}

func (analyzer *BlueTeamTrafficAnalyzer) printResults(nmapScanDetected map[string]int, arpPoisoningDetected map[string]string, icmpTunnelDetected int, dnsTunnelDetected int, anomalyDetected map[string]int) {
	fmt.Println("\n=== Analysis Results ===")

	fmt.Println("\nNmap Scan Detection:")
	for scanType, count := range nmapScanDetected {
		fmt.Printf("  %s scans detected: %d\n", scanType, count)
	}

	fmt.Println("\nARP Poisoning Detection:")
	if len(arpPoisoningDetected) > 0 {
		for ip, mac := range arpPoisoningDetected {
			fmt.Printf("  Suspicious ARP Entry: IP - %s, MAC - %s\n", ip, mac)
		}
	} else {
		fmt.Println("  No ARP poisoning detected.")
	}

	fmt.Printf("\nICMP Tunneling Detection: %d\n", icmpTunnelDetected)
	fmt.Printf("\nDNS Tunneling Detection: %d\n", dnsTunnelDetected)

	fmt.Println("\nAnomaly Detection:")
	for ip, count := range anomalyDetected {
		if count > 100 {
			fmt.Printf("  Anomalous activity detected from IP: %s\n", ip)
		}
	}
}

func (analyzer *BlueTeamTrafficAnalyzer) GenerateJSONReport(packetReports []PacketInfo) {
	outputDir := "reports"
	os.MkdirAll(outputDir, os.ModePerm)

	outputFile := filepath.Join(outputDir, fmt.Sprintf("report_%s.json", time.Now().Format("20060102_150405")))
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed to create JSON report file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(packetReports); err != nil {
		log.Fatalf("Failed to write JSON report: %v", err)
	}

	fmt.Printf("\nJSON report generated: %s\n", outputFile)
}

func main() {
	var filePath string
	flag.StringVar(&filePath, "file", "", "Path to a single pcap file")
	flag.Parse()

	if filePath == "" {
		fmt.Println("Error: You must specify a pcap file with --file")
		os.Exit(1)
	}

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer handle.Close()

	analyzer := &BlueTeamTrafficAnalyzer{FilePath: filePath}
	packetReports, err := analyzer.AnalyzePackets(handle)
	if err != nil {
		log.Fatalf("Error analyzing packets: %v", err)
	}

	analyzer.GenerateJSONReport(packetReports)
}
