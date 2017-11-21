// Package sflow provides support for parsing SFLOW messages and reporting the
// results. This package supports the SFLOW protocol as defined by RFC 1034
// and RFC 1035. It does not have any special support for RFC 2671 (ESFLOW) or
// RFC 4035 (SFLOW Security Extensions), but since those specifications only
// add backwards compatible features there will be no issues handling the
// messages.
package sflow

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/monitoring"
	"github.com/elastic/beats/packetbeat/publish"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"

	lxp "github.com/lflxp/sflow"
)

type sflowPlugin struct {
	// Configuration data.
	ports              []int
	sendRequest        bool
	sendResponse       bool
	includeAuthorities bool
	includeAdditionals bool

	// Cache of active SFLOW transactions. The map key is the HashableSflowTuple
	// associated with the request.
	transactions       *common.Cache
	transactionTimeout time.Duration

	results publish.Transactions // Channel where results are pushed.
}

const maxSFLOWPacketSize = (1 << 16) // 65535 (bytes)
const maxSFLOWTupleRawSize = 16 + 16 + 2 + 2 + 4 + 1

// Constants used to associate the SFLOW QR flag with a meaningful value.
const (
	query    = false
	response = true
)

// Transport protocol.
type transport uint8

var (
	unmatchedRequests  = monitoring.NewInt(nil, "sflow.unmatched_requests")
	transportNames = []string{
		"tcp",
		"udp",
	}
	debugf = logp.MakeDebug("sflow")
)

const (
	transportTCP = iota
	transportUDP
)

func (t transport) String() string {
	if int(t) >= len(transportNames) {
		return "impossible"
	}
	return transportNames[t]
}

type hashableSFLOWTuple [maxSFLOWTupleRawSize]byte

// SflowMessage contains a single SFLOW message.
type sflowMessage struct {
	ts           time.Time          // Time when the message was received.
	tuple        common.IPPortTuple // Source and destination addresses of packet.
	cmdlineTuple *common.CmdlineTuple
	samples      *[]lxp.FlowSamples // Parsed SFLOW packet data.
	counters     *[]lxp.SFlowCounterSample // Parsed SFLOW packet data.
	length       int        // Length of the SFLOW message in bytes (without DecodeOffset).
}

// SflowTuple contains source IP/port, destination IP/port, transport protocol,
// and SFLOW ID.
type sflowTuple struct {
	ipLength         int
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	transport        transport
	id               uint16

	raw    hashableSFLOWTuple // Src_ip:Src_port:Dst_ip:Dst_port:Transport:Id
}

func sflowTupleFromIPPort(t *common.IPPortTuple, trans transport) sflowTuple {
	tuple := sflowTuple{
		ipLength:  t.IPLength,
		srcIP:     t.SrcIP,
		dstIP:     t.DstIP,
		srcPort:   t.SrcPort,
		dstPort:   t.DstPort,
		transport: trans,
	}
	tuple.computeHashebles()

	return tuple
}

func (t *sflowTuple) computeHashebles() {
	copy(t.raw[0:16], t.srcIP)
	copy(t.raw[16:18], []byte{byte(t.srcPort >> 8), byte(t.srcPort)})
	copy(t.raw[18:34], t.dstIP)
	copy(t.raw[34:36], []byte{byte(t.dstPort >> 8), byte(t.dstPort)})
	copy(t.raw[36:38], []byte{byte(t.id >> 8), byte(t.id)})
	t.raw[39] = byte(t.transport)
}

func (t *sflowTuple) String() string {
	return fmt.Sprintf("SflowTuple src[%s:%d] dst[%s:%d] transport[%s] id[%d]",
		t.srcIP.String(),
		t.srcPort,
		t.dstIP.String(),
		t.dstPort,
		t.transport,
		t.id)
}

// Hashable returns a hashable value that uniquely identifies
// the SFLOW tuple.
func (t *sflowTuple) hashable() hashableSFLOWTuple {
	return t.raw
}

// getTransaction returns the transaction associated with the given
// HashableSflowTuple. The lookup key should be the HashableSflowTuple associated
// with the request (src is the requestor). Nil is returned if the entry
// does not exist.
func (sflow *sflowPlugin) getTransaction(k hashableSFLOWTuple) *sflowTransaction {
	v := sflow.transactions.Get(k)
	if v != nil {
		return v.(*sflowTransaction)
	}
	return nil
}

type sflowTransaction struct {
	ts           time.Time // Time when the request was received.
	tuple        sflowTuple  // Key used to track this transaction in the transactionsMap.
	responseTime int32     // Elapsed time in milliseconds between the request and response.
	src          common.Endpoint
	dst          common.Endpoint
	transport    transport
	notes        []string

	request      *sflowMessage
}

func init() {
	protos.Register("sflow", New)
}

func New(
	testMode bool,
	results publish.Transactions,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &sflowPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (sflow *sflowPlugin) init(results publish.Transactions, config *sflowConfig) error {
	sflow.setFromConfig(config)
	sflow.transactions = common.NewCacheWithRemovalListener(
		sflow.transactionTimeout,
		protos.DefaultTransactionHashSize,
		func(k common.Key, v common.Value) {
			trans, ok := v.(*sflowTransaction)
			if !ok {
				logp.Err("Expired value is not a *SflowTransaction.")
				return
			}
			sflow.expireTransaction(trans)
		})
	sflow.transactions.StartJanitor(sflow.transactionTimeout)

	sflow.results = results

	return nil
}

func (sflow *sflowPlugin) setFromConfig(config *sflowConfig) error {
	sflow.ports = config.Ports
	sflow.sendRequest = config.SendRequest
	sflow.sendResponse = config.SendResponse
	sflow.includeAuthorities = config.IncludeAuthorities
	sflow.includeAdditionals = config.IncludeAdditionals
	sflow.transactionTimeout = config.TransactionTimeout
	return nil
}

func newTransaction(ts time.Time, tuple sflowTuple, cmd common.CmdlineTuple) *sflowTransaction {
	trans := &sflowTransaction{
		transport: tuple.transport,
		ts:        ts,
		tuple:     tuple,
	}
	trans.src = common.Endpoint{
		IP:   tuple.srcIP.String(),
		Port: tuple.srcPort,
		Proc: string(cmd.Src),
	}
	trans.dst = common.Endpoint{
		IP:   tuple.dstIP.String(),
		Port: tuple.dstPort,
		Proc: string(cmd.Dst),
	}
	return trans
}

// deleteTransaction deletes an entry from the transaction map and returns
// the deleted element. If the key does not exist then nil is returned.
func (sflow *sflowPlugin) deleteTransaction(k hashableSFLOWTuple) *sflowTransaction {
	v := sflow.transactions.Delete(k)
	if v != nil {
		return v.(*sflowTransaction)
	}
	return nil
}

func (sflow *sflowPlugin) GetPorts() []int {
	return sflow.ports
}

func (sflow *sflowPlugin) ConnectionTimeout() time.Duration {
	return sflow.transactionTimeout
}

func (sflow *sflowPlugin) receivedSFLOWRequest(tuple *sflowTuple, msg *sflowMessage) {
	debugf("Processing query. %s", tuple.String())

	trans := sflow.deleteTransaction(tuple.hashable())
	if trans != nil {
		// This happens if a client puts multiple requests in flight
		// with the same ID.
		trans.notes = append(trans.notes, duplicateQueryMsg.Error())
		debugf("%s %s", duplicateQueryMsg.Error(), tuple.String())
		sflow.publishTransaction(trans)
		sflow.deleteTransaction(trans.tuple.hashable())
	}

	trans = newTransaction(msg.ts, *tuple, *msg.cmdlineTuple)

	if tuple.transport == transportUDP && msg.length > maxSFLOWPacketSize {
		trans.notes = append(trans.notes, udpPacketTooLarge.Error())
		debugf("%s", udpPacketTooLarge.Error())
	}

	sflow.transactions.Put(tuple.hashable(), trans)
	trans.request = msg
}

func (sflow *sflowPlugin) publishTransaction(t *sflowTransaction) {
	if sflow.results == nil {
		return
	}

	debugf("Publishing transaction. %s", t.tuple.String())

	if len(*t.request.samples) > 0 {
		for _,sa := range *t.request.samples {
			fields := common.MapStr{}
			fields["@timestamp"] = common.Time(t.ts)
			fields["type"] = "sflow"
			fields["transport"] = t.transport.String()
			fields["src"] = &t.src
			fields["dst"] = &t.dst
			fields["status"] = common.ERROR_STATUS
			if len(t.notes) == 1 {
				fields["notes"] = t.notes[0]
			} else if len(t.notes) > 1 {
				fields["notes"] = strings.Join(t.notes, " ")
			}

			sflowEvent := common.MapStr{}
			fields["sflow"] = sflowEvent


			//sflow agent info
			fields["Datagram"] = common.MapStr{
					"IPLength":  sa.Data.Datagram.IPLength,
					"SrcIP":  sa.Data.Datagram.SrcIP,
					"DstIP":  sa.Data.Datagram.DstIP,
					"SrcPort":  sa.Data.Datagram.SrcPort,
					"DstPort":  sa.Data.Datagram.DstPort,
				}

			//SFlow info
			fields["type"] = sa.Data.Type
			fields["DatagramVersion"] = sa.Data.DatagramVersion
			fields["AgentAddress"] = sa.Data.AgentAddress
			fields["SubAgentID"] = sa.Data.SubAgentID
			fields["SequenceNumber"] = sa.Data.SequenceNumber
			fields["AgentUptime"] = sa.Data.AgentUptime
			fields["SampleCount"] = sa.Data.SampleCount
			fields["EnterpriseID"] = sa.EnterpriseID
			fields["Format"] = sa.Format
			fields["SampleLength"] = sa.SampleLength
			fields["SequenceNumber"] = sa.SequenceNumber
			fields["SourceIDClass"] = sa.SourceIDClass
			fields["SourceIDIndex"] = sa.SourceIDIndex
			fields["SamplingRate"] = sa.SamplingRate
			fields["SamplePool"] = sa.SamplePool
			fields["Dropped"] = sa.Dropped
			fields["InputInterfaceFormat"] = sa.InputInterfaceFormat
			fields["InputInterface"] = sa.InputInterface
			fields["OutputInterfaceFormat"] = sa.OutputInterfaceFormat
			fields["OutputInterface"] = sa.OutputInterface
			fields["RecordCount"] = sa.RecordCount

			//SFlowRawPacketFlowRecord
			fields["SFlowRawPacketFlowRecord"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  sa.SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.EnterpriseID,
					"Format":  sa.SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.Format,
					"FlowDataLength":  sa.SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.FlowDataLength,
				},
				"HeaderProtocol": sa.SFlowRawPacketFlowRecord.HeaderProtocol,
				"FrameLength": sa.SFlowRawPacketFlowRecord.FrameLength,
				"PayloadRemoved": sa.SFlowRawPacketFlowRecord.PayloadRemoved,
				"HeaderLength": sa.SFlowRawPacketFlowRecord.HeaderLength,
				"Header": common.MapStr{
					"FlowRecords": sa.SFlowRawPacketFlowRecord.Header.FlowRecords,
					"Packets": sa.SFlowRawPacketFlowRecord.Header.Packets,
					"Bytes": sa.SFlowRawPacketFlowRecord.Header.Bytes,
					"RateBytes": sa.SFlowRawPacketFlowRecord.Header.RateBytes,
					"SrcMac": sa.SFlowRawPacketFlowRecord.Header.SrcMac,
					"DstMac": sa.SFlowRawPacketFlowRecord.Header.DstMac,
					"SrcIP": sa.SFlowRawPacketFlowRecord.Header.SrcIP,
					"DstIP": sa.SFlowRawPacketFlowRecord.Header.DstIP,
					"Ipv4_version": sa.SFlowRawPacketFlowRecord.Header.Ipv4_version,
					"Ipv4_ihl": sa.SFlowRawPacketFlowRecord.Header.Ipv4_ihl,
					"Ipv4_tos": sa.SFlowRawPacketFlowRecord.Header.Ipv4_tos,
					"Ipv4_ttl": sa.SFlowRawPacketFlowRecord.Header.Ipv4_ttl,
					"Ipv4_protocol": sa.SFlowRawPacketFlowRecord.Header.Ipv4_protocol,
					"SrcPort": sa.SFlowRawPacketFlowRecord.Header.SrcPort,
					"DstPort": sa.SFlowRawPacketFlowRecord.Header.DstPort,
				},
			}

			//SFlowExtendedSwitchFlowRecord
			fields["SFlowExtendedSwitchFlowRecord"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  sa.SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.EnterpriseID,
					"Format":  sa.SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.Format,
					"FlowDataLength":  sa.SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.FlowDataLength,
				},
				"IncomingVLAN": sa.SFlowExtendedSwitchFlowRecord.IncomingVLAN,
				"IncomingVLANPriority": sa.SFlowExtendedSwitchFlowRecord.IncomingVLANPriority,
				"OutgoingVLAN": sa.SFlowExtendedSwitchFlowRecord.OutgoingVLAN,
				"OutgoingVLANPriority": sa.SFlowExtendedSwitchFlowRecord.OutgoingVLANPriority,
			}

			//SFlowExtendedRouterFlowRecord
			fields["SFlowExtendedRouterFlowRecord"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  sa.SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.EnterpriseID,
					"Format":  sa.SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.Format,
					"FlowDataLength":  sa.SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.FlowDataLength,
				},
				"NextHop": sa.SFlowExtendedRouterFlowRecord.NextHop,
				"NextHopSourceMask": sa.SFlowExtendedRouterFlowRecord.NextHopSourceMask,
				"NextHopDestinationMask": sa.SFlowExtendedRouterFlowRecord.NextHopDestinationMask,
			}

			//SFlowExtendedGatewayFlowRecord
			fields["SFlowExtendedGatewayFlowRecord"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  sa.SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.EnterpriseID,
					"Format":  sa.SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.Format,
					"FlowDataLength":  sa.SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.FlowDataLength,
				},
				"NextHop": sa.SFlowExtendedGatewayFlowRecord.NextHop,
				"AS": sa.SFlowExtendedGatewayFlowRecord.AS,
				"SourceAS": sa.SFlowExtendedGatewayFlowRecord.SourceAS,
				"PeerAS": sa.SFlowExtendedGatewayFlowRecord.PeerAS,
				"ASPathCount": sa.SFlowExtendedGatewayFlowRecord.ASPathCount,
				"ASPath": sa.SFlowExtendedGatewayFlowRecord.ASPath,
				"Communities": sa.SFlowExtendedGatewayFlowRecord.Communities,
				"LocalPref": sa.SFlowExtendedGatewayFlowRecord.LocalPref,
			}

			//SFlowExtendedUserFlow
			fields["SFlowExtendedUserFlow"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  sa.SFlowExtendedUserFlow.SFlowBaseFlowRecord.EnterpriseID,
					"Format":  sa.SFlowExtendedUserFlow.SFlowBaseFlowRecord.Format,
					"FlowDataLength":  sa.SFlowExtendedUserFlow.SFlowBaseFlowRecord.FlowDataLength,
				},
				"SourceCharSet": sa.SFlowExtendedUserFlow.SourceCharSet,
				"SourceUserID": sa.SFlowExtendedUserFlow.SourceUserID,
				"DestinationCharSet": sa.SFlowExtendedUserFlow.DestinationCharSet,
				"DestinationUserID": sa.SFlowExtendedUserFlow.DestinationUserID,
			}
			sflow.results.PublishTransaction(fields)
		}
	}

	if len(*t.request.counters) > 0 {
		for _,counter := range *t.request.counters {
			fields := common.MapStr{}
			fields["@timestamp"] = common.Time(t.ts)
			fields["type"] = "sflow"
			fields["transport"] = t.transport.String()
			fields["src"] = &t.src
			fields["dst"] = &t.dst
			fields["status"] = common.ERROR_STATUS
			if len(t.notes) == 1 {
				fields["notes"] = t.notes[0]
			} else if len(t.notes) > 1 {
				fields["notes"] = strings.Join(t.notes, " ")
			}

			sflowEvent := common.MapStr{}
			fields["sflow"] = sflowEvent


			//sflow agent info
			fields["Data"] = common.MapStr{
					"IPLength":  counter.Data.Datagram.IPLength,
					"SrcIP":  counter.Data.Datagram.SrcIP,
					"DstIP":  counter.Data.Datagram.DstIP,
					"SrcPort":  counter.Data.Datagram.SrcPort,
					"DstPort":  counter.Data.Datagram.DstPort,
				}

			//SFlow info
			fields["type"] = counter.Data.Type
			fields["DatagramVersion"] = counter.Data.DatagramVersion
			fields["AgentAddress"] = counter.Data.AgentAddress
			fields["SubAgentID"] = counter.Data.SubAgentID
			fields["SequenceNumber"] = counter.Data.SequenceNumber
			fields["AgentUptime"] = counter.Data.AgentUptime
			fields["SampleCount"] = counter.Data.SampleCount
			fields["EnterpriseID"] = counter.EnterpriseID
			fields["Format"] = counter.Format
			fields["SampleLength"] = counter.SampleLength
			fields["SequenceNumber"] = counter.SequenceNumber
			fields["SourceIDClass"] = counter.SourceIDClass
			fields["SourceIDIndex"] = counter.SourceIDIndex
			fields["RecordCount"] = counter.RecordCount

			//SFlowGenericInterfaceCounters
			fields["SFlowGenericInterfaceCounters"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  counter.SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.EnterpriseID,
					"Format":  counter.SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.Format,
					"FlowDataLength":  counter.SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.FlowDataLength,
				},
				"IfIndex": counter.SFlowGenericInterfaceCounters.IfIndex,
				"IfType": counter.SFlowGenericInterfaceCounters.IfType,
				"IfSpeed": counter.SFlowGenericInterfaceCounters.IfSpeed,
				"IfDirection": counter.SFlowGenericInterfaceCounters.IfDirection,
				"IfStatus": counter.SFlowGenericInterfaceCounters.IfStatus,
				"IfInOctets": counter.SFlowGenericInterfaceCounters.IfInOctets,
				"IfInUcastPkts": counter.SFlowGenericInterfaceCounters.IfInUcastPkts,
				"IfInMulticastPkts": counter.SFlowGenericInterfaceCounters.IfInMulticastPkts,
				"IfInBroadcastPkts": counter.SFlowGenericInterfaceCounters.IfInBroadcastPkts,
				"IfInDiscards": counter.SFlowGenericInterfaceCounters.IfInDiscards,
				"IfInErrors": counter.SFlowGenericInterfaceCounters.IfInErrors,
				"IfInUnknownProtos": counter.SFlowGenericInterfaceCounters.IfInUnknownProtos,
				"IfOutOctets": counter.SFlowGenericInterfaceCounters.IfOutOctets,
				"IfOutUcastPkts": counter.SFlowGenericInterfaceCounters.IfOutUcastPkts,
				"IfOutMulticastPkts": counter.SFlowGenericInterfaceCounters.IfOutMulticastPkts,
				"IfOutBroadcastPkts": counter.SFlowGenericInterfaceCounters.IfOutBroadcastPkts,
				"IfOutDiscards": counter.SFlowGenericInterfaceCounters.IfOutDiscards,
				"IfOutErrors": counter.SFlowGenericInterfaceCounters.IfOutErrors,
				"IfPromiscuousMode": counter.SFlowGenericInterfaceCounters.IfPromiscuousMode,
			}

			//SFlowEthernetCounters
			fields["SFlowEthernetCounters"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  counter.SFlowEthernetCounters.SFlowBaseCounterRecord.EnterpriseID,
					"Format":  counter.SFlowEthernetCounters.SFlowBaseCounterRecord.Format,
					"FlowDataLength":  counter.SFlowEthernetCounters.SFlowBaseCounterRecord.FlowDataLength,
				},
				"AlignmentErrors": counter.SFlowEthernetCounters.AlignmentErrors,
				"FCSErrors": counter.SFlowEthernetCounters.FCSErrors,
				"SingleCollisionFrames": counter.SFlowEthernetCounters.SingleCollisionFrames,
				"MultipleCollisionFrames": counter.SFlowEthernetCounters.MultipleCollisionFrames,
				"SQETestErrors": counter.SFlowEthernetCounters.SQETestErrors,
				"DeferredTransmissions": counter.SFlowEthernetCounters.DeferredTransmissions,
				"LateCollisions": counter.SFlowEthernetCounters.LateCollisions,
				"ExcessiveCollisions": counter.SFlowEthernetCounters.ExcessiveCollisions,
				"InternalMacTransmitErrors": counter.SFlowEthernetCounters.InternalMacTransmitErrors,
				"CarrierSenseErrors": counter.SFlowEthernetCounters.CarrierSenseErrors,
				"FrameTooLongs": counter.SFlowEthernetCounters.FrameTooLongs,
				"InternalMacReceiveErrors": counter.SFlowEthernetCounters.InternalMacReceiveErrors,
				"SymbolErrors": counter.SFlowEthernetCounters.SymbolErrors,
			}

			//SFlowProcessorCounters
			fields["SFlowProcessorCounters"] = common.MapStr{
				"SFlowBaseFlowRecord": 	common.MapStr{
					"EnterpriseID":  counter.SFlowProcessorCounters.SFlowBaseCounterRecord.EnterpriseID,
					"Format":  counter.SFlowProcessorCounters.SFlowBaseCounterRecord.Format,
					"FlowDataLength":  counter.SFlowProcessorCounters.SFlowBaseCounterRecord.FlowDataLength,
				},
				"FiveSecCpu": counter.SFlowProcessorCounters.FiveSecCpu,
				"OneMinCpu": counter.SFlowProcessorCounters.OneMinCpu,
				"FiveMinCpu": counter.SFlowProcessorCounters.FiveMinCpu,
				"TotalMemory": counter.SFlowProcessorCounters.TotalMemory,
				"FreeMemory": counter.SFlowProcessorCounters.FreeMemory,
			}
			sflow.results.PublishTransaction(fields)
		}
	}
}

func (sflow *sflowPlugin) expireTransaction(t *sflowTransaction) {
	t.notes = append(t.notes, noResponse.Error())
	debugf("%s %s", noResponse.Error(), t.tuple.String())
	sflow.publishTransaction(t)
	unmatchedRequests.Add(1)
}


func (sflow *sflowPlugin) ParseUDP(pkt *protos.Packet) {
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
	} else {
		sflowTuple := sflowTupleFromIPPort(&pkt.Tuple, transportUDP)
		sflowMsg := &sflowMessage{
			ts:           pkt.Ts,
			tuple:        pkt.Tuple,
			cmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
			samples:      sample,
			counters:     counter,
			length:       packetSize,
		}
		sflow.receivedSFLOWRequest(&sflowTuple, sflowMsg)
	}
}
