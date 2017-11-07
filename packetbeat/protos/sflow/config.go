package sflow

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

//ProtocolCommon struct
type sflowConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = sflowConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)

