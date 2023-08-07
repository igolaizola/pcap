package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type entry struct {
	time     time.Time
	duration time.Duration
}

// RequestDuration prints the duration of requests and responses in a pcap file
// searching for packets with the given ip address and payload size.
func RequestDuration(ctx context.Context, file, ip string, reqMin, reqMax, respMin, respMax int) error {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return err
	}
	defer handle.Close()

	var entries []entry
	var curr *time.Time

	for {
		data, ci, err := handle.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		pack := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		ipLayer, ok := pack.NetworkLayer().(*layers.IPv4)
		if !ok {
			continue
		}
		srcIP := ipLayer.SrcIP.String()
		dstIP := ipLayer.DstIP.String()
		if srcIP != ip && dstIP != ip {
			continue
		}

		tcpLayer, ok := pack.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}
		n := len(tcpLayer.Payload)
		switch {
		case srcIP == ip && n >= reqMin && n <= reqMax:
			curr = &ci.Timestamp
		case dstIP == ip && n >= respMin && n <= respMax && curr != nil:
			entries = append(entries, entry{
				time:     *curr,
				duration: ci.Timestamp.Sub(*curr),
			})
			curr = nil
		default:
			continue
		}
		fmt.Println(ci.Timestamp.UTC().Format(time.RFC3339Nano), srcIP, dstIP, ci.Length, n)
	}

	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		fmt.Println(e.time.UTC().Format(time.RFC3339Nano), e.duration)
	}
	return nil
}
