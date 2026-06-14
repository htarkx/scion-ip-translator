package srcgo

import (
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

var _ = daemon.NewAutoConnector()
var _ = addr.AS
var _ = snet.Network

type Mapping struct {
	IPv6    string `yaml:"ipv6"`
	ScionIA string `yaml:"scion_ia"`
}
