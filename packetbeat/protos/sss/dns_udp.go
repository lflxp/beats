package dns

import (
	"github.com/elastic/beats/libbeat/logp"

	//"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	//"encoding/json"
	lxp "github.com/lflxp/sflow"
	//"fmt"
	"github.com/elastic/beats/packetbeat/procs"
)

// Only EDNS packets should have their size beyond this value
const maxDNSPacketSize = (1 << 9) // 512 (bytes)

func (dns *dnsPlugin) ParseUDP(pkt *protos.Packet) {
	defer logp.Recover("Dns ParseUdp")
	packetSize := len(pkt.Payload)

	debugf("Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), packetSize)

	tuple := lxp.Datagram{}
	tuple.IPLength = pkt.Tuple.IPLength
	tuple.SrcIP = pkt.Tuple.SrcIP
	tuple.DstIP = pkt.Tuple.DstIP
	tuple.SrcPort = pkt.Tuple.SrcPort
	tuple.DstPort = pkt.Tuple.DstPort

	sample,counter, err := lxp.DecodeSflow(&tuple, pkt.Payload)
	if err != nil {
		debugf(err.Error())
	}

	//b, err := json.Marshal(samples)
	//if err != nil {
	//	fmt.Println(err.Error())
	//}
	//
	//fmt.Println(string(b))

	dnsTuple := dnsTupleFromIPPort(&pkt.Tuple, transportUDP)
	dnsMsg := &dnsMessage{
		ts:           pkt.Ts,
		tuple:        pkt.Tuple,
		cmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
		samples:      sample,
		counters:     counter,
		length:       packetSize,
	}

	dns.receivedDNSRequest(&dnsTuple, dnsMsg)
}
