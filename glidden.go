package main

import (
	"code.google.com/p/gopacket/layers"
	"encoding/json"
	"github.com/armon/consul-api"
	"github.com/openshift/geard/pkg/go-netfilter-queue"
	"log"
	"net"
	"time"
)

type Cidr net.IPNet

func (ip *Cidr) UnmarshalJSON(bytes []byte) error {
	data := ""
	if err := json.Unmarshal(bytes, &data); err != nil {
		return err
	} else if _, ipnet, err2 := net.ParseCIDR(data); err2 != nil {
		return err
	} else {
		*ip = Cidr(*ipnet)
		return nil
	}
}

func consulKeys(key string) chan []Cidr {
	ch := make(chan []Cidr)
	queryopts := consulapi.QueryOptions{WaitTime: 30e9}
	go func(key string) {
		for {
			client, err := consulapi.NewClient(consulapi.DefaultConfig())
			if err == nil {
				kv := client.KV()
				for {
					value, queryinfo, err := kv.Get(key, &queryopts)
					if err != nil {
						log.Fatalf("Getting", err)
					}
					cidrs := make([]Cidr, 0, 0)
					err = json.Unmarshal(value.Value, &cidrs)
					if err != nil {
						log.Fatalf("Unmarshaling", err)
					}
					queryopts.WaitIndex = queryinfo.LastIndex
					ch <- cidrs
				}
			} else {
				log.Printf("Could not connect to consul %s", err)
				time.Sleep(3000 * time.Millisecond)
			}
		}
	}(key)
	return ch
}

func main() {
	var err error

	allow := consulKeys("allow")
	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("Error creating queue", err)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()
	cidrs := make([]Cidr, 0, 0)
	var address net.IP
loop:
	for true {
		select {
		case cidrs = <-allow:
			log.Printf("Recieved %d cidrs", len(cidrs))
		case packet := <-packets:
			layer := packet.Packet.NetworkLayer()
			src, _ := layer.NetworkFlow().Endpoints()
			if _, ok := layer.(*layers.IPv4); ok {
				address = net.IP(src.Raw()[0:4])
			} else {
				address = net.IP(src.Raw()[0:16])
			}
			for _, cidr := range cidrs {
				ipnet := net.IPNet(cidr)
				if ipnet.Contains(address) {
					log.Printf("Allowing because %q contains %q", ipnet, address)
					packet.SetVerdict(netfilter.NF_ACCEPT)
					continue loop
				}
			}
			log.Printf("Rejecting %q", address)
			packet.SetVerdict(netfilter.NF_DROP)
		}
	}
}
