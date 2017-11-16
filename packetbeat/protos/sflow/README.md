#### Only support UDP

**Parsing**

1. Attempt to decode each UDP packet.
2. If it succeeds, a transaction is sent.

**Error management**
* Debug information is printed if:
  * A packet fails to decode.

* Error Notes are published if:
  * Never
  
#### Layers

##### Sample

Only decoder five layers of sflow sample

>SFlowRawPacketFlowRecord
SFlowExtendedSwitchFlowRecord
SFlowExtendedRouterFlowRecord
SFlowExtendedGatewayFlowRecord
SFlowExtendedUserFlow

##### Counter

decoder all of layers

>SFlowGenericInterfaceCounters
SFlowEthernetCounters
SFlowProcessorCounters

#### TODO

**General**
* Publish an event with Notes when a Query or a lone Response cannot be decoded.
* Consider adding ICMP support to
     - correlate ICMP type 3, code 4 (datagram too big) with DNS messages,
     - correlate ICMP type 3, code 13 (administratively prohibited) or
       ICMP type 3, code 3 (port unreachable) with blocked DNS messages.
