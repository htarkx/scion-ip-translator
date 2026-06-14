package srcgo

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Loader struct {
	egressObjs  EgressObjects
	ingressObjs IngressObjects
	egressLink  link.Link
	ingressLink link.Link
}

func NewLoader(egressIf string, ingressIf string) (*Loader, error) {
	var egressObjs EgressObjects
	var ingressObjs IngressObjects
	err := LoadEgressObjects(&egressObjs, nil)
	if err != nil {
		return nil, err
	}
	err = LoadIngressObjects(&ingressObjs, nil)
	if err != nil {
		return nil, err
	}
	ifnameEgress, err := net.InterfaceByName(egressIf)
	if err != nil {
		return nil, err
	}
	ifnameIngress, err := net.InterfaceByName(ingressIf)
	if err != nil {
		return nil, err
	}
	e, err := link.AttachTCX(link.TCXOptions{
		Program:   egressObjs.EgressPrograms.ScionEgress,
		Attach:    ebpf.AttachTCXEgress,
		Interface: ifnameEgress.Index,
		Anchor:    link.Tail(),
	})
	if err != nil {
		return nil, err
	}
	i, err := link.AttachXDP(link.XDPOptions{
		Program:   ingressObjs.IngressPrograms.ScionIngress,
		Interface: ifnameIngress.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, err
	}
	return &Loader{
		egressObjs:  egressObjs,
		ingressObjs: ingressObjs,
		egressLink:  e,
		ingressLink: i,
	}, nil
}
func (l *Loader) EgressMaps() *EgressMaps {
	return &l.egressObjs.EgressMaps
}

func (l *Loader) Close() error {
	err := l.egressObjs.Close()
	if err != nil {
		return err
	}
	err = l.ingressObjs.Close()
	if err != nil {
		return err
	}
	err = l.egressLink.Close()
	if err != nil {
		return err
	}
	err = l.ingressLink.Close()
	if err != nil {
		return err
	}
	return nil
}
