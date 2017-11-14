package sflow

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

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
