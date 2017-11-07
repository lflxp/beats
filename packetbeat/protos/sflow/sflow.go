package sflow

import (
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/publish"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

type sflowPlugin struct {
	Name 	string
}

func init() {
	protos.Register("sflow", New)
}

func New(testMode bool, results publish.TransactionPublisher, cfg *common.Config) (protos.Plugin, error) {
	p := &Sflow{}
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

func (this *sflowPlugin) init(results protos.Reporter, config *sflowConfig) error {
	this.setFromConfig(config)
	this.transactions = common.NewCacheWithRemovalListener(
		this.transactionTimeout,
		protos.DefaultTransactionHashSize,
		func(k common.Key, v common.Value) {
			trans, ok := v.(*sflow)
			if !ok {
				logp.Err("Expired value is not a *DnsTransaction.")
				return
			}
			dns.expireTransaction(trans)
		})
	this.transactions.StartJanitor(this.transactionTimeout)

	this.results = results

	return nil
}
