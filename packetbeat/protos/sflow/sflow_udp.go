package sflow

import (
	"fmt"
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

	datas, err := lxp.DecodeSflow(&pkt.Tuple, pkt.Payload)
	if err != nil {
		debugf(err.Error())
	}
	for _, jsons := range datas {
		fmt.Println(jsons)
	}
}
