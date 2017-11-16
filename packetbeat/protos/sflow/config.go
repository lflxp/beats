package sflow

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type sflowConfig struct {
	config.ProtocolCommon `config:",inline"`
	IncludeAuthorities    bool `config:"include_authorities"`
	IncludeAdditionals    bool `config:"include_additionals"`
}

var (
	defaultConfig = sflowConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)
