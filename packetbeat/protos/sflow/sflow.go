// Package sflow provides support for parsing SFLOW V5 messages and reporting the
// results. This package supports the SFLOW protocol as defined by RFC 3176.
package sflow

import (
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"time"

	"github.com/elastic/beats/packetbeat/protos"
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

// decodeDnsData decodes a byte array into a SFLOW V5 struct.
// but this parsing function will drop some data which decode errors is
// skipping TypeEthernetFrameFlow,and where is flowRecordType equal 2.
//func decodeSFlowData(transp transport, rawData []byte)
