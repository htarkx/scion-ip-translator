package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	srcgo "github.com/htarkx/scion-ip-translator/loader"
	"github.com/scionproto/scion/pkg/daemon"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Mappings  []srcgo.Mapping `yaml:"mappings"`
	EgressIf  string          `yaml:"egress_if"`
	IngressIf string          `yaml:"ingress_if"`
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	daemonAddr := flag.String("daemon", "[::1]:30255", "SCION daemon address host:port")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	conn, err := daemon.NewAutoConnector(ctx, daemon.WithDaemon(*daemonAddr))
	if err != nil {
		log.Fatalf("daemon connect: %v", err)
	}

	localIA, err := conn.LocalIA(ctx)
	if err != nil {
		log.Fatalf("get local IA: %v", err)
	}
	log.Printf("local IA: %s", localIA)

	loader, err := srcgo.NewLoader(cfg.EgressIf, cfg.IngressIf)
	if err != nil {
		log.Fatalf("load BPF: %v", err)
	}
	defer loader.Close()
	log.Printf("BPF programs attached: egress=%s ingress=%s", cfg.EgressIf, cfg.IngressIf)

	maps := loader.EgressMaps()
	addrToIA, err := srcgo.PopulateIpv6Map(maps, cfg.Mappings)
	if err != nil {
		log.Fatalf("populate ipv6 map: %v", err)
	}
	log.Printf("ipv6_to_scion map populated: %d entries", len(cfg.Mappings))

	log.Println("listening for path requests from BPF...")
	if err := srcgo.ListenPathReq(ctx, conn, localIA, maps, addrToIA); err != nil {
		log.Fatalf("path req listener: %v", err)
	}
}
