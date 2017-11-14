package sflow
// decodeDnsData decodes a byte array into a SFLOW V5 struct.
// but this parsing function will drop some data which decode errors is
// skipping TypeEthernetFrameFlow,and where is flowRecordType equal 2.
import (
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/protos"
	lxp "github.com/lflxp/sflow"
)

// Only EDNS packets should have their size beyond this value
const maxDNSPacketSize = (1 << 9) // 512 (bytes)

func (sflow *sflowPlugin) ParseUDP(pkt *protos.Packet) {
	defer logp.Recover("Sflow ParseUdp")
	packetSize := len(pkt.Payload)

	debugf("Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), packetSize)

	tuple := lxp.Datagram{}
	tuple.IPLength = pkt.Tuple.IPLength
	tuple.SrcIP = pkt.Tuple.SrcIP
	tuple.DstIP = pkt.Tuple.DstIP
	tuple.SrcPort = pkt.Tuple.SrcPort
	tuple.DstPort = pkt.Tuple.DstPort

	samples,counters, err := lxp.DecodeSflow(&tuple, pkt.Payload)
	if err != nil {
		debugf(err.Error())
	}
	//for _, jsons := range datas {
	//	fmt.Println(jsons)
	//}
	sflow.publishTransaction(samples,counters)
}
