// Package dns provides support for parsing DNS messages and reporting the
// results. This package supports the DNS protocol as defined by RFC 1034
// and RFC 1035. It does not have any special support for RFC 2671 (EDNS) or
// RFC 4035 (DNS Security Extensions), but since those specifications only
// add backwards compatible features there will be no issues handling the
// messages.
package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/monitoring"

	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/publish"

	lxp "github.com/lflxp/sflow"
)

type dnsPlugin struct {
	// Configuration data.
	ports              []int
	sendRequest        bool
	sendResponse       bool
	includeAuthorities bool
	includeAdditionals bool

	// Cache of active DNS transactions. The map key is the HashableDnsTuple
	// associated with the request.
	transactions       *common.Cache
	transactionTimeout time.Duration

	results publish.Transactions // Channel where results are pushed.
}

var (
	debugf = logp.MakeDebug("sss")
)

const maxDNSTupleRawSize = 16 + 16 + 2 + 2 + 4 + 1

// Constants used to associate the DNS QR flag with a meaningful value.
const (
	query    = false
	response = true
)

// Transport protocol.
type transport uint8

var (
	unmatchedRequests  = monitoring.NewInt(nil, "sss.unmatched_requests")
	unmatchedResponses = monitoring.NewInt(nil, "sss.unmatched_responses")
)

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

type hashableDNSTuple [maxDNSTupleRawSize]byte

// DnsMessage contains a single DNS message.
type dnsMessage struct {
	ts           time.Time          // Time when the message was received.
	tuple        common.IPPortTuple // Source and destination addresses of packet.
	cmdlineTuple *common.CmdlineTuple
	samples         []*lxp.FlowSamples // Parsed DNS packet data.
	counters         []*lxp.SFlowCounterSample // Parsed DNS packet data.
	length       int        // Length of the DNS message in bytes (without DecodeOffset).
}

// DnsTuple contains source IP/port, destination IP/port, transport protocol,
// and DNS ID.
type dnsTuple struct {
	ipLength         int
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	transport        transport
	id               uint16

	raw    hashableDNSTuple // Src_ip:Src_port:Dst_ip:Dst_port:Transport:Id
	revRaw hashableDNSTuple // Dst_ip:Dst_port:Src_ip:Src_port:Transport:Id
}

func dnsTupleFromIPPort(t *common.IPPortTuple, trans transport) dnsTuple {
	tuple := dnsTuple{
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

func (t dnsTuple) reverse() dnsTuple {
	return dnsTuple{
		ipLength:  t.ipLength,
		srcIP:     t.dstIP,
		dstIP:     t.srcIP,
		srcPort:   t.dstPort,
		dstPort:   t.srcPort,
		transport: t.transport,
		id:        t.id,
		raw:       t.revRaw,
		revRaw:    t.raw,
	}
}

func (t *dnsTuple) computeHashebles() {
	copy(t.raw[0:16], t.srcIP)
	copy(t.raw[16:18], []byte{byte(t.srcPort >> 8), byte(t.srcPort)})
	copy(t.raw[18:34], t.dstIP)
	copy(t.raw[34:36], []byte{byte(t.dstPort >> 8), byte(t.dstPort)})
	copy(t.raw[36:38], []byte{byte(t.id >> 8), byte(t.id)})
	t.raw[39] = byte(t.transport)

	copy(t.revRaw[0:16], t.dstIP)
	copy(t.revRaw[16:18], []byte{byte(t.dstPort >> 8), byte(t.dstPort)})
	copy(t.revRaw[18:34], t.srcIP)
	copy(t.revRaw[34:36], []byte{byte(t.srcPort >> 8), byte(t.srcPort)})
	copy(t.revRaw[36:38], []byte{byte(t.id >> 8), byte(t.id)})
	t.revRaw[39] = byte(t.transport)
}

func (t *dnsTuple) String() string {
	return fmt.Sprintf("DnsTuple src[%s:%d] dst[%s:%d] transport[%s] id[%d]",
		t.srcIP.String(),
		t.srcPort,
		t.dstIP.String(),
		t.dstPort,
		t.transport,
		t.id)
}

// Hashable returns a hashable value that uniquely identifies
// the DNS tuple.
func (t *dnsTuple) hashable() hashableDNSTuple {
	return t.raw
}

// Hashable returns a hashable value that uniquely identifies
// the DNS tuple after swapping the source and destination.
func (t *dnsTuple) revHashable() hashableDNSTuple {
	return t.revRaw
}

// getTransaction returns the transaction associated with the given
// HashableDnsTuple. The lookup key should be the HashableDnsTuple associated
// with the request (src is the requestor). Nil is returned if the entry
// does not exist.
func (dns *dnsPlugin) getTransaction(k hashableDNSTuple) *dnsTransaction {
	v := dns.transactions.Get(k)
	if v != nil {
		return v.(*dnsTransaction)
	}
	return nil
}

type dnsTransaction struct {
	ts           time.Time // Time when the request was received.
	tuple        dnsTuple  // Key used to track this transaction in the transactionsMap.
	responseTime int32     // Elapsed time in milliseconds between the request and response.
	src          common.Endpoint
	dst          common.Endpoint
	transport    transport
	notes        []string

	sample       []*lxp.FlowSamples
	counter      []*lxp.SFlowCounterSample
}

func init() {
	protos.Register("sss", New)
}

func New(
	testMode bool,
	results publish.Transactions,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &dnsPlugin{}
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

func (dns *dnsPlugin) init(results publish.Transactions, config *dnsConfig) error {
	dns.setFromConfig(config)
	dns.transactions = common.NewCacheWithRemovalListener(
		dns.transactionTimeout,
		protos.DefaultTransactionHashSize,
		func(k common.Key, v common.Value) {
			trans, ok := v.(*dnsTransaction)
			if !ok {
				logp.Err("Expired value is not a *DnsTransaction.")
				return
			}
			dns.expireTransaction(trans)
		})
	dns.transactions.StartJanitor(dns.transactionTimeout)

	dns.results = results

	return nil
}

func (dns *dnsPlugin) setFromConfig(config *dnsConfig) error {
	dns.ports = config.Ports
	dns.sendRequest = config.SendRequest
	dns.sendResponse = config.SendResponse
	dns.includeAuthorities = config.IncludeAuthorities
	dns.includeAdditionals = config.IncludeAdditionals
	dns.transactionTimeout = config.TransactionTimeout
	return nil
}

func newTransaction(ts time.Time, tuple dnsTuple, cmd common.CmdlineTuple) *dnsTransaction {
	trans := &dnsTransaction{
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
func (dns *dnsPlugin) deleteTransaction(k hashableDNSTuple) *dnsTransaction {
	v := dns.transactions.Delete(k)
	if v != nil {
		return v.(*dnsTransaction)
	}
	return nil
}

func (dns *dnsPlugin) GetPorts() []int {
	return dns.ports
}

func (dns *dnsPlugin) ConnectionTimeout() time.Duration {
	return dns.transactionTimeout
}

func (dns *dnsPlugin) receivedDNSRequest(tuple *dnsTuple, msg *dnsMessage) {
	debugf("Processing query. %s", tuple.String())

	trans := dns.deleteTransaction(tuple.hashable())
	if trans != nil {
		// This happens if a client puts multiple requests in flight
		// with the same ID.
		trans.notes = append(trans.notes, duplicateQueryMsg.Error())
		debugf("%s %s", duplicateQueryMsg.Error(), tuple.String())
		dns.publishTransaction(trans)
		dns.deleteTransaction(trans.tuple.hashable())
	}

	trans = newTransaction(msg.ts, *tuple, *msg.cmdlineTuple)

	if tuple.transport == transportUDP && msg.length > maxDNSPacketSize {
		trans.notes = append(trans.notes, udpPacketTooLarge.Error())
		debugf("%s", udpPacketTooLarge.Error())
	}

	dns.transactions.Put(tuple.hashable(), trans)
	trans.sample = msg.samples
	trans.counter = msg.counters
}

//func (dns *dnsPlugin) receivedDNSResponse(tuple *dnsTuple, msg *dnsMessage) {
//	debugf("Processing response. %s", tuple.String())
//
//	trans := dns.getTransaction(tuple.revHashable())
//	if trans == nil {
//		trans = newTransaction(msg.ts, tuple.reverse(), common.CmdlineTuple{
//			Src: msg.cmdlineTuple.Dst, Dst: msg.cmdlineTuple.Src})
//		trans.notes = append(trans.notes, orphanedResponse.Error())
//		debugf("%s %s", orphanedResponse.Error(), tuple.String())
//		unmatchedResponses.Add(1)
//	}
//
//	trans.sample = msg
//
//	if tuple.transport == transportUDP {
//		respIsEdns := msg.data.IsEdns0() != nil
//		if !respIsEdns && msg.length > maxDNSPacketSize {
//			trans.notes = append(trans.notes, udpPacketTooLarge.responseError())
//			debugf("%s", udpPacketTooLarge.responseError())
//		}
//
//		request := trans.request
//		if request != nil {
//			reqIsEdns := request.data.IsEdns0() != nil
//
//			switch {
//			case reqIsEdns && !respIsEdns:
//				trans.notes = append(trans.notes, respEdnsNoSupport.Error())
//				debugf("%s %s", respEdnsNoSupport.Error(), tuple.String())
//			case !reqIsEdns && respIsEdns:
//				trans.notes = append(trans.notes, respEdnsUnexpected.Error())
//				debugf("%s %s", respEdnsUnexpected.Error(), tuple.String())
//			}
//		}
//	}
//
//	dns.publishTransaction(trans)
//	dns.deleteTransaction(trans.tuple.hashable())
//}

func (dns *dnsPlugin) publishTransaction(t *dnsTransaction) {
	if dns.results == nil {
		return
	}

	debugf("Publishing transaction. %s", t.tuple.String())

	if len(t.sample) > 0 {
		for _,sa := range t.sample {
			fields := common.MapStr{}
			fields["@timestamp"] = common.Time(t.ts)
			fields["type"] = "sss"
			fields["transport"] = t.transport.String()
			fields["src"] = &t.src
			fields["dst"] = &t.dst
			fields["status"] = common.ERROR_STATUS
			if len(t.notes) == 1 {
				fields["notes"] = t.notes[0]
			} else if len(t.notes) > 1 {
				fields["notes"] = strings.Join(t.notes, " ")
			}

			dnsEvent := common.MapStr{}
			fields["sss"] = dnsEvent


			//sflow agent info
			fields["Data.Datagram.IPLength"] = sa.Data.Datagram.IPLength
			fields["Data.Datagram.SrcIP"] = sa.Data.Datagram.SrcIP
			fields["Data.Datagram.DstIP"] = sa.Data.Datagram.DstIP
			fields["Data.Datagram.SrcPort"] = sa.Data.Datagram.SrcPort
			fields["Data.Datagram.DstPort"] = sa.Data.Datagram.DstPort

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
			dns.results.PublishTransaction(fields)
		}
	}

	if len(t.counter) > 0 {
		for _,counter := range t.counter {
			fields := common.MapStr{}
			fields["@timestamp"] = common.Time(t.ts)
			fields["type"] = "sss"
			fields["transport"] = t.transport.String()
			fields["src"] = &t.src
			fields["dst"] = &t.dst
			fields["status"] = common.ERROR_STATUS
			if len(t.notes) == 1 {
				fields["notes"] = t.notes[0]
			} else if len(t.notes) > 1 {
				fields["notes"] = strings.Join(t.notes, " ")
			}

			dnsEvent := common.MapStr{}
			fields["sss"] = dnsEvent


			//sflow agent info
			fields["Data.Datagram.IPLength"] = counter.Data.Datagram.IPLength
			fields["Data.Datagram.SrcIP"] = sa.Data.Datagram.SrcIP
			fields["Data.Datagram.DstIP"] = sa.Data.Datagram.DstIP
			fields["Data.Datagram.SrcPort"] = sa.Data.Datagram.SrcPort
			fields["Data.Datagram.DstPort"] = sa.Data.Datagram.DstPort

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
			dns.results.PublishTransaction(fields)
		}
	}
}

func (dns *dnsPlugin) expireTransaction(t *dnsTransaction) {
	t.notes = append(t.notes, noResponse.Error())
	debugf("%s %s", noResponse.Error(), t.tuple.String())
	dns.publishTransaction(t)
	unmatchedRequests.Add(1)
}
