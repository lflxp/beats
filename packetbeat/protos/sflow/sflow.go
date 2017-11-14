// Package sflow provides support for parsing SFLOW V5 messages and reporting the
// results. This package supports the SFLOW protocol as defined by RFC 3176.
package sflow

import (
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"time"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/libbeat/beat"
	lxp "github.com/lflxp/sflow"
	"errors"
	"fmt"
	"net"
)

type sflowPlugin struct {
	// Configuration data.
	ports        []int
	sendRequest  bool
	sendResponse bool

	transactionTimeout time.Duration

	results protos.Reporter // Channel where results are pushed.
}

var (
	debugf = logp.MakeDebug("sflow")
)

// Transport protocol.
type transport uint8

const (
	transportTCP = iota
	transportUDP
)

var transportNames = []string{
	"tcp",
	"udp",
}

func (t transport) String() string {
	if int(t) >= len(transportNames) {
		return "impossible"
	}
	return transportNames[t]
}

func init() {
	protos.Register("sflow", New)
}

func New(
	testMode bool,
	results protos.Reporter,
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

func (sflow *sflowPlugin) init(results protos.Reporter, config *sflowConfig) error {
	sflow.setFromConfig(config)
	sflow.results = results

	return nil
}

//获取传递的配置信息
func (sflow *sflowPlugin) setFromConfig(config *sflowConfig) error {
	sflow.ports = config.Ports
	sflow.sendRequest = config.SendRequest
	sflow.sendResponse = config.SendResponse
	sflow.transactionTimeout = config.TransactionTimeout
	return nil
}

func (sflow *sflowPlugin) GetPorts() []int {
	return sflow.ports
}

func (sflow *sflowPlugin) decoerSample(t []*lxp.FlowSamples) ([]*common.MapStr,time.Time,error) {
	timestamp := time.Now()
	if len(t) == 0 {
		return nil,timestamp,errors.New("Length is 0")
	}

	result := []*common.MapStr{}
	debugf("Publishing transaction Sample. %d", len(t))

	for _,sa := range t {
		fields := common.MapStr{}
		//sflow agent info
		fields["Data.Data.Datagram.IPLength"] = sa.Data.Datagram.IPLength
		fields["Data.Data.Datagram.SrcIP"] = sa.Data.Datagram.SrcIP
		fields["Data.Data.Datagram.DstIP"] = sa.Data.Datagram.DstIP
		fields["Data.Data.Datagram.SrcPort"] = sa.Data.Datagram.SrcPort
		fields["Data.Data.Datagram.DstPort"] = sa.Data.Datagram.DstPort

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
		fields["SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.EnterpriseID"] = sa.SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.EnterpriseID
		fields["SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.Format"] = sa.SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.Format
		fields["SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.FlowDataLength"] = sa.SFlowRawPacketFlowRecord.SFlowBaseFlowRecord.FlowDataLength
		fields["SFlowRawPacketFlowRecord.HeaderProtocol"] = sa.SFlowRawPacketFlowRecord.HeaderProtocol
		fields["SFlowRawPacketFlowRecord.FrameLength"] = sa.SFlowRawPacketFlowRecord.FrameLength
		fields["SFlowRawPacketFlowRecord.PayloadRemoved"] = sa.SFlowRawPacketFlowRecord.PayloadRemoved
		fields["SFlowRawPacketFlowRecord.HeaderLength"] = sa.SFlowRawPacketFlowRecord.HeaderLength
		fields["SFlowRawPacketFlowRecord.Header.FlowRecords"] = sa.SFlowRawPacketFlowRecord.Header.FlowRecords
		fields["SFlowRawPacketFlowRecord.Header.Packets"] = sa.SFlowRawPacketFlowRecord.Header.Packets
		fields["SFlowRawPacketFlowRecord.Header.Bytes"] = sa.SFlowRawPacketFlowRecord.Header.Bytes
		fields["SFlowRawPacketFlowRecord.Header.RateBytes"] = sa.SFlowRawPacketFlowRecord.Header.RateBytes
		fields["SFlowRawPacketFlowRecord.Header.SrcMac"] = sa.SFlowRawPacketFlowRecord.Header.SrcMac
		fields["SFlowRawPacketFlowRecord.Header.DstMac"] = sa.SFlowRawPacketFlowRecord.Header.DstMac
		fields["SFlowRawPacketFlowRecord.Header.SrcIP"] = sa.SFlowRawPacketFlowRecord.Header.SrcIP
		fields["SFlowRawPacketFlowRecord.Header.DstIP"] = sa.SFlowRawPacketFlowRecord.Header.DstIP
		fields["SFlowRawPacketFlowRecord.Header.Ipv4_version"] = sa.SFlowRawPacketFlowRecord.Header.Ipv4_version
		fields["SFlowRawPacketFlowRecord.Header.Ipv4_ihl"] = sa.SFlowRawPacketFlowRecord.Header.Ipv4_ihl
		fields["SFlowRawPacketFlowRecord.Header.Ipv4_tos"] = sa.SFlowRawPacketFlowRecord.Header.Ipv4_tos
		fields["SFlowRawPacketFlowRecord.Header.Ipv4_ttl"] = sa.SFlowRawPacketFlowRecord.Header.Ipv4_ttl
		fields["SFlowRawPacketFlowRecord.Header.Ipv4_protocol"] = sa.SFlowRawPacketFlowRecord.Header.Ipv4_protocol
		fields["SFlowRawPacketFlowRecord.Header.SrcPort"] = sa.SFlowRawPacketFlowRecord.Header.SrcPort
		fields["SFlowRawPacketFlowRecord.Header.DstPort"] = sa.SFlowRawPacketFlowRecord.Header.DstPort

		//SFlowExtendedSwitchFlowRecord
		fields["SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.EnterpriseID"] = sa.SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.EnterpriseID
		fields["SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.Format"] = sa.SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.Format
		fields["SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.FlowDataLength"] = sa.SFlowExtendedSwitchFlowRecord.SFlowBaseFlowRecord.FlowDataLength
		fields["SFlowExtendedSwitchFlowRecord.IncomingVLAN"] = sa.SFlowExtendedSwitchFlowRecord.IncomingVLAN
		fields["SFlowExtendedSwitchFlowRecord.IncomingVLANPriority"] = sa.SFlowExtendedSwitchFlowRecord.IncomingVLANPriority
		fields["SFlowExtendedSwitchFlowRecord.OutgoingVLAN"] = sa.SFlowExtendedSwitchFlowRecord.OutgoingVLAN
		fields["SFlowExtendedSwitchFlowRecord.OutgoingVLANPriority"] = sa.SFlowExtendedSwitchFlowRecord.OutgoingVLANPriority

		//SFlowExtendedRouterFlowRecord
		fields["SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.EnterpriseID"] = sa.SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.EnterpriseID
		fields["SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.Format"] = sa.SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.Format
		fields["SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.FlowDataLength"] = sa.SFlowExtendedRouterFlowRecord.SFlowBaseFlowRecord.FlowDataLength
		fields["SFlowExtendedRouterFlowRecord.NextHop"] = sa.SFlowExtendedRouterFlowRecord.NextHop
		fields["SFlowExtendedRouterFlowRecord.NextHopSourceMask"] = sa.SFlowExtendedRouterFlowRecord.NextHopSourceMask
		fields["SFlowExtendedRouterFlowRecord.NextHopDestinationMask"] = sa.SFlowExtendedRouterFlowRecord.NextHopDestinationMask

		//SFlowExtendedGatewayFlowRecord
		fields["SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.EnterpriseID"] = sa.SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.EnterpriseID
		fields["SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.Format"] = sa.SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.Format
		fields["SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.FlowDataLength"] = sa.SFlowExtendedGatewayFlowRecord.SFlowBaseFlowRecord.FlowDataLength
		fields["SFlowExtendedGatewayFlowRecord.NextHop"] = sa.SFlowExtendedGatewayFlowRecord.NextHop
		fields["SFlowExtendedGatewayFlowRecord.AS"] = sa.SFlowExtendedGatewayFlowRecord.AS
		fields["SFlowExtendedGatewayFlowRecord.SourceAS"] = sa.SFlowExtendedGatewayFlowRecord.SourceAS
		fields["SFlowExtendedGatewayFlowRecord.PeerAS"] = sa.SFlowExtendedGatewayFlowRecord.PeerAS
		fields["SFlowExtendedGatewayFlowRecord.ASPathCount"] = sa.SFlowExtendedGatewayFlowRecord.ASPathCount
		fields["SFlowExtendedGatewayFlowRecord.ASPath"] = sa.SFlowExtendedGatewayFlowRecord.ASPath
		fields["SFlowExtendedGatewayFlowRecord.Communities"] = sa.SFlowExtendedGatewayFlowRecord.Communities
		fields["SFlowExtendedGatewayFlowRecord.LocalPref"] = sa.SFlowExtendedGatewayFlowRecord.LocalPref

		//SFlowExtendedUserFlow
		fields["SFlowExtendedUserFlow.SFlowBaseFlowRecord.EnterpriseID"] = sa.SFlowExtendedUserFlow.SFlowBaseFlowRecord.EnterpriseID
		fields["SFlowExtendedUserFlow.SFlowBaseFlowRecord.Format"] = sa.SFlowExtendedUserFlow.SFlowBaseFlowRecord.Format
		fields["SFlowExtendedUserFlow.SFlowBaseFlowRecord.FlowDataLength"] = sa.SFlowExtendedUserFlow.SFlowBaseFlowRecord.FlowDataLength
		fields["SFlowExtendedUserFlow.SourceCharSet"] = sa.SFlowExtendedUserFlow.SourceCharSet
		fields["SFlowExtendedUserFlow.SourceUserID"] = sa.SFlowExtendedUserFlow.SourceUserID
		fields["SFlowExtendedUserFlow.DestinationCharSet"] = sa.SFlowExtendedUserFlow.DestinationCharSet
		fields["SFlowExtendedUserFlow.DestinationUserID"] = sa.SFlowExtendedUserFlow.DestinationUserID

		result = append(result,&fields)
	}
	return result,timestamp,nil
}

func (sflow *sflowPlugin) decoderCounter(counters []*lxp.SFlowCounterSample) ([]*common.MapStr,time.Time,error) {
	timestamp := time.Now()
	if len(counters) == 0 {
		return nil,timestamp,errors.New("Length is 0")
	}

	result := []*common.MapStr{}
	debugf("Publishing transaction Counter. %d", len(counters))

	for _,sa := range counters {
		fields := common.MapStr{}
		//sflow agent info
		fields["Data.Data.Datagram.IPLength"] = sa.Data.Datagram.IPLength
		fields["Data.Data.Datagram.SrcIP"] = sa.Data.Datagram.SrcIP
		fields["Data.Data.Datagram.DstIP"] = sa.Data.Datagram.DstIP
		fields["Data.Data.Datagram.SrcPort"] = sa.Data.Datagram.SrcPort
		fields["Data.Data.Datagram.DstPort"] = sa.Data.Datagram.DstPort

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
		fields["RecordCount"] = sa.RecordCount

		//SFlowGenericInterfaceCounters
		fields["SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.EnterpriseID"] = sa.SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.EnterpriseID
		fields["SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.Format"] = sa.SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.Format
		fields["SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.FlowDataLength"] = sa.SFlowGenericInterfaceCounters.SFlowBaseCounterRecord.FlowDataLength
		fields["SFlowGenericInterfaceCounters.IfIndex"] = sa.SFlowGenericInterfaceCounters.IfIndex
		fields["SFlowGenericInterfaceCounters.IfType"] = sa.SFlowGenericInterfaceCounters.IfType
		fields["SFlowGenericInterfaceCounters.IfSpeed"] = sa.SFlowGenericInterfaceCounters.IfSpeed
		fields["SFlowGenericInterfaceCounters.IfDirection"] = sa.SFlowGenericInterfaceCounters.IfDirection
		fields["SFlowGenericInterfaceCounters.IfStatus"] = sa.SFlowGenericInterfaceCounters.IfStatus
		fields["SFlowGenericInterfaceCounters.IfInOctets"] = sa.SFlowGenericInterfaceCounters.IfInOctets
		fields["SFlowGenericInterfaceCounters.IfInUcastPkts"] = sa.SFlowGenericInterfaceCounters.IfInUcastPkts
		fields["SFlowGenericInterfaceCounters.IfInMulticastPkts"] = sa.SFlowGenericInterfaceCounters.IfInMulticastPkts
		fields["SFlowGenericInterfaceCounters.IfInBroadcastPkts"] = sa.SFlowGenericInterfaceCounters.IfInBroadcastPkts
		fields["SFlowGenericInterfaceCounters.IfInDiscards"] = sa.SFlowGenericInterfaceCounters.IfInDiscards
		fields["SFlowGenericInterfaceCounters.IfInErrors"] = sa.SFlowGenericInterfaceCounters.IfInErrors
		fields["SFlowGenericInterfaceCounters.IfInUnknownProtos"] = sa.SFlowGenericInterfaceCounters.IfInUnknownProtos
		fields["SFlowGenericInterfaceCounters.IfOutOctets"] = sa.SFlowGenericInterfaceCounters.IfOutOctets
		fields["SFlowGenericInterfaceCounters.IfOutUcastPkts"] = sa.SFlowGenericInterfaceCounters.IfOutUcastPkts
		fields["SFlowGenericInterfaceCounters.IfOutMulticastPkts"] = sa.SFlowGenericInterfaceCounters.IfOutMulticastPkts
		fields["SFlowGenericInterfaceCounters.IfOutBroadcastPkts"] = sa.SFlowGenericInterfaceCounters.IfOutBroadcastPkts
		fields["SFlowGenericInterfaceCounters.IfOutDiscards"] = sa.SFlowGenericInterfaceCounters.IfOutDiscards
		fields["SFlowGenericInterfaceCounters.IfOutErrors"] = sa.SFlowGenericInterfaceCounters.IfOutErrors
		fields["SFlowGenericInterfaceCounters.IfPromiscuousMode"] = sa.SFlowGenericInterfaceCounters.IfPromiscuousMode

		//SFlowEthernetCounters
		fields["SFlowEthernetCounters.SFlowBaseCounterRecord.EnterpriseID"] = sa.SFlowEthernetCounters.SFlowBaseCounterRecord.EnterpriseID
		fields["SFlowEthernetCounters.SFlowBaseCounterRecord.Format"] = sa.SFlowEthernetCounters.SFlowBaseCounterRecord.Format
		fields["SFlowEthernetCounters.SFlowBaseCounterRecord.FlowDataLength"] = sa.SFlowEthernetCounters.SFlowBaseCounterRecord.FlowDataLength
		fields["SFlowEthernetCounters.AlignmentErrors"] = sa.SFlowEthernetCounters.AlignmentErrors
		fields["SFlowEthernetCounters.FCSErrors"] = sa.SFlowEthernetCounters.FCSErrors
		fields["SFlowEthernetCounters.SingleCollisionFrames"] = sa.SFlowEthernetCounters.SingleCollisionFrames
		fields["SFlowEthernetCounters.MultipleCollisionFrames"] = sa.SFlowEthernetCounters.MultipleCollisionFrames
		fields["SFlowEthernetCounters.SQETestErrors"] = sa.SFlowEthernetCounters.SQETestErrors
		fields["SFlowEthernetCounters.DeferredTransmissions"] = sa.SFlowEthernetCounters.DeferredTransmissions
		fields["SFlowEthernetCounters.LateCollisions"] = sa.SFlowEthernetCounters.LateCollisions
		fields["SFlowEthernetCounters.ExcessiveCollisions"] = sa.SFlowEthernetCounters.ExcessiveCollisions
		fields["SFlowEthernetCounters.InternalMacTransmitErrors"] = sa.SFlowEthernetCounters.InternalMacTransmitErrors
		fields["SFlowEthernetCounters.CarrierSenseErrors"] = sa.SFlowEthernetCounters.CarrierSenseErrors
		fields["SFlowEthernetCounters.FrameTooLongs"] = sa.SFlowEthernetCounters.FrameTooLongs
		fields["SFlowEthernetCounters.InternalMacReceiveErrors"] = sa.SFlowEthernetCounters.InternalMacReceiveErrors
		fields["SFlowEthernetCounters.SymbolErrors"] = sa.SFlowEthernetCounters.SymbolErrors

		//SFlowProcessorCounters
		fields["SFlowProcessorCounters.SFlowBaseCounterRecord.EnterpriseID"] = sa.SFlowProcessorCounters.SFlowBaseCounterRecord.EnterpriseID
		fields["SFlowProcessorCounters.SFlowBaseCounterRecord.Format"] = sa.SFlowProcessorCounters.SFlowBaseCounterRecord.Format
		fields["SFlowProcessorCounters.SFlowBaseCounterRecord.FlowDataLength"] = sa.SFlowProcessorCounters.SFlowBaseCounterRecord.FlowDataLength
		fields["SFlowProcessorCounters.FiveSecCpu"] = sa.SFlowProcessorCounters.FiveSecCpu
		fields["SFlowProcessorCounters.OneMinCpu"] = sa.SFlowProcessorCounters.OneMinCpu
		fields["SFlowProcessorCounters.FiveMinCpu"] = sa.SFlowProcessorCounters.FiveMinCpu
		fields["SFlowProcessorCounters.TotalMemory"] = sa.SFlowProcessorCounters.TotalMemory
		fields["SFlowProcessorCounters.FreeMemory"] = sa.SFlowProcessorCounters.FreeMemory

		result = append(result,&fields)
	}
	return  result,timestamp,nil
}

func (sflow *sflowPlugin) publishTransaction(samples []*lxp.FlowSamples,counters []*lxp.SFlowCounterSample) {
	if sflow.results == nil {
		return
	}

	CountSamples,DataTime,err := sflow.decoerSample(samples)
	if err != nil {
		debugf(err.Error())
	} else {
		for _,datas := range CountSamples {
			sflow.results(beat.Event{
				Timestamp: DataTime,
				Fields:    *datas,
			})
		}
	}
	CountCounters,DataTime,err := sflow.decoderCounter(counters)
	if err != nil {
		debugf(err.Error())
	} else {
		for _,datas := range CountCounters {
			sflow.results(beat.Event{
				Timestamp: DataTime,
				Fields:    *datas,
			})
		}
	}
}


//func newTransaction(ts time.Time, tuple sflowTuple, cmd common.CmdlineTuple) *sflowTransaction {
//	trans := &sflowTransaction{
//		transport: tuple.transport,
//		ts:        ts,
//		tuple:     tuple,
//	}
//	trans.src = common.Endpoint{
//		IP:   tuple.srcIP.String(),
//		Port: tuple.srcPort,
//		Proc: string(cmd.Src),
//	}
//	trans.dst = common.Endpoint{
//		IP:   tuple.dstIP.String(),
//		Port: tuple.dstPort,
//		Proc: string(cmd.Dst),
//	}
//	return trans
//}

type sflowTransaction struct {
	ts           time.Time // Time when the request was received.
	tuple        sflowTuple  // Key used to track this transaction in the transactionsMap.
	responseTime int32     // Elapsed time in milliseconds between the request and response.
	src          common.Endpoint
	dst          common.Endpoint
	transport    transport
	notes        []string

	sample		*[]lxp.FlowSamples
	counter 	*[]lxp.SFlowCounterSample
}

// sflowTuple contains source IP/port, destination IP/port, transport protocol,
// and SFLOW ID.
type sflowTuple struct {
	ipLength         int
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	transport        transport
}

func dnsTupleFromIPPort(t *common.IPPortTuple, trans transport) sflowTuple {
	tuple := sflowTuple{
		ipLength:  t.IPLength,
		srcIP:     t.SrcIP,
		dstIP:     t.DstIP,
		srcPort:   t.SrcPort,
		dstPort:   t.DstPort,
		transport: trans,
	}

	return tuple
}

func (sft *sflowTuple) String() string {
	return fmt.Sprintf("SflowTuple src[%s:%d] dst[%s:%d] transport[%s]",
		sft.srcIP.String(),
		sft.srcPort,
		sft.dstIP.String(),
		sft.dstPort,
		sft.transport)
}
