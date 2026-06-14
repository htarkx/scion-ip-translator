package srcgo

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
	scionpath "github.com/scionproto/scion/pkg/snet/path"
)

type Mapping struct {
	Prefix  string `yaml:"prefix"`
	ScionIA string `yaml:"scion_ia"`
}

// lossless direction of the conversion, see the next function for the lossy direction.
func u32_to_ia(u uint32) addr.IA {
	return addr.MustIAFrom(
		addr.ISD(u>>20&0xFFF),
		addr.AS(u&0xFFFFF),
	)
}

// TODO: This is lossy due to BPF-prgramme uses only 32 bits for IA. Fix needed for standard compliance.
func ia_to_u32(ia addr.IA) uint32 {
	return uint32(ia.AS()) | uint32(ia.ISD())<<20
}

func cidrToLpmKey(cidr string) (EgressLpmKeyV6, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return EgressLpmKeyV6{}, err
	}
	ones, _ := ipnet.Mask.Size()
	var key EgressLpmKeyV6
	key.Prefixlen = uint32(ones)
	copy(key.Addr.In6U.U6Addr8[:], ipnet.IP.To16())
	return key, nil
}

// PopulateIpv6Map fills the BPF LPM map and returns a reverse-lookup table
// from the compressed scion_addr (u32) back to the full IA. The reverse map
// is needed because the u32 compression is lossy (only 20 AS bits).
func PopulateIpv6Map(maps *EgressMaps, mappings []Mapping) (map[uint32]addr.IA, error) {
	addrToIA := make(map[uint32]addr.IA, len(mappings))
	for _, mapping := range mappings {
		key, err := cidrToLpmKey(mapping.Prefix)
		if err != nil {
			return nil, err
		}
		ia := addr.MustParseIA(mapping.ScionIA)
		value := ia_to_u32(ia)
		if err := maps.Ipv6ToScion.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return nil, err
		}
		addrToIA[value] = ia
	}
	return addrToIA, nil
}

// iaNetBytes packs ISD+AS into 8 big-endian wire bytes, then reads them back
// as a little-endian uint64 so that when stored in BPF map memory on x86 the
// underlying bytes remain in network byte order.
func iaNetBytes(ia addr.IA) uint64 {
	var b [8]byte
	binary.BigEndian.PutUint16(b[0:2], uint16(ia.ISD()))
	as := uint64(ia.AS())
	b[2] = byte(as >> 40)
	b[3] = byte(as >> 32)
	b[4] = byte(as >> 24)
	b[5] = byte(as >> 16)
	b[6] = byte(as >> 8)
	b[7] = byte(as)
	return binary.LittleEndian.Uint64(b[:])
}

// buildPathEntry converts a snet.Path into an EgressPathMapEntry ready to be
// written into the BPF path_map.
func buildPathEntry(p snet.Path, localIA addr.IA) (EgressPathMapEntry, error) {
	sp, ok := p.Dataplane().(scionpath.SCION)
	if !ok {
		return EgressPathMapEntry{}, errors.New("unsupported path type: expected SCION")
	}
	rawPath := sp.Raw
	if len(rawPath)%4 != 0 {
		return EgressPathMapEntry{}, errors.New("path length not 4-byte aligned")
	}
	if len(rawPath) > 255*4 {
		return EgressPathMapEntry{}, errors.New("path too long for BPF map")
	}

	nextHop := p.UnderlayNextHop()
	if nextHop == nil {
		return EgressPathMapEntry{}, errors.New("no underlay next hop")
	}

	var entry EgressPathMapEntry
	// total SCION hdr = common(12) + ISD-AS(16) + IPv6 hosts(2*16=32) + path bytes
	entry.Header.Len = uint8((60 + len(rawPath)) / 4)
	// SC_PATH_TYPE_SCION = 1
	entry.Header.Type = 1
	// DT=0, DL=3 (IPv6=16B), ST=0, SL=3 (IPv6=16B) → 0x33
	entry.Header.Haddr = 0x33
	entry.Header.Dst.Dst = iaNetBytes(p.Destination())
	entry.Header.Src.Src = iaNetBytes(localIA)

	// Copy raw path bytes into [255]uint32 preserving wire byte order.
	// binary.LittleEndian.Uint32 reinterprets [B0,B1,B2,B3] as a LE uint32
	// whose memory layout on x86 is exactly [B0,B1,B2,B3]. ✓
	entry.PathLen = uint8(len(rawPath) / 4)
	for i := range entry.PathLen {
		entry.Path[i] = binary.LittleEndian.Uint32(rawPath[i*4:])
	}

	copy(entry.RouterAddr[:], nextHop.IP.To16())
	// router_port in host byte order; BPF applies bpf_htons before writing to packet.
	entry.RouterPort = uint16(nextHop.Port)
	return entry, nil
}

func queryAndCachePath(ctx context.Context, conn daemon.Connector, localIA addr.IA, addrToIA map[uint32]addr.IA, scionAddr uint32, maps *EgressMaps) error {
	dstIA, ok := addrToIA[scionAddr]
	if !ok {
		// Lossy fallback — likely wrong for standard AS numbers.
		dstIA = u32_to_ia(scionAddr)
		log.Printf("path_req: scion_addr=0x%08x not in addrToIA map, falling back to %s", scionAddr, dstIA)
	}
	log.Printf("path_req: querying paths to %s (scion_addr=0x%08x)", dstIA, scionAddr)
	paths, err := conn.Paths(ctx, dstIA, localIA, types.PathReqFlags{})
	if err != nil {
		log.Printf("path_req: conn.Paths error: %v", err)
		return err
	}
	if len(paths) == 0 {
		log.Printf("path_req: no paths to %s", dstIA)
		return errors.New("no paths to " + dstIA.String())
	}
	log.Printf("path_req: %d paths to %s, using first; next_hop=%v", len(paths), dstIA, paths[0].UnderlayNextHop())
	entry, err := buildPathEntry(paths[0], localIA)
	if err != nil {
		log.Printf("path_req: buildPathEntry error: %v", err)
		return err
	}
	if err := maps.PathMap.Update(&scionAddr, &entry, ebpf.UpdateAny); err != nil {
		log.Printf("path_req: path_map update error: %v", err)
		return err
	}
	log.Printf("path_req: path_map updated for %s", dstIA)
	return nil
}

// listenPathReq reads scion_addr requests from the BPF path_req ring buffer
// and populates path_map via the SCION daemon. Blocks until ctx is cancelled.
func ListenPathReq(ctx context.Context, conn daemon.Connector, localIA addr.IA, maps *EgressMaps, addrToIA map[uint32]addr.IA) error {
	rd, err := ringbuf.NewReader(maps.PathReq)
	if err != nil {
		return err
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		if len(rec.RawSample) < 4 {
			continue
		}
		scionAddr := binary.LittleEndian.Uint32(rec.RawSample[:4])
		log.Printf("ringbuf: got path_req for scion_addr=0x%08x", scionAddr)
		// Ignore per-request errors; BPF will re-request on next packet.
		_ = queryAndCachePath(ctx, conn, localIA, addrToIA, scionAddr, maps)
	}
}
