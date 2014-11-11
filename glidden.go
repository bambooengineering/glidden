package main

import (
	"encoding/json"
	"fmt"
	"github.com/armon/consul-api"
	"github.com/openshift/geard/pkg/go-netfilter-queue"
	"net"
	"os"
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
	go func(key string) {
		opts := consulapi.QueryOptions{}
		for {
			client, err := consulapi.NewClient(consulapi.DefaultConfig())
			if err == nil {
				kv := client.KV()
				for {
					value, queryinfo, err2 := kv.Get(key, &opts)
					cidrs := make([]Cidr, 0, 0)
					err3 := json.Unmarshal(value.Value, &cidrs)
					if err2 == nil && err3 == nil {
						opts.WaitIndex = queryinfo.LastIndex
						ch <- cidrs
					} else if err2 == nil && err3 != nil {
						opts.WaitIndex = queryinfo.LastIndex
						fmt.Printf("Could not parse %s, (%s)", value, err3)
					} else {
						fmt.Printf("Could not get from %s, (%s)", key, err2)
					}
				}
			} else {
				fmt.Printf("Could not connect to consul %s", err)
				time.Sleep(3000 * time.Millisecond)
			}
		}
	}(key)
	return ch
}

func main() {
	var err error

	allow := consulKeys("allow")
	nfq, err := netfilter.NewNFQueue(1, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()
	cidrs := make([]Cidr, 0, 0)

	for true {
		select {
		case cidrs = <-allow:
		case packet := <-packets:
			// fmt.Println(p.Packet)
			for _, cidr := range cidrs {
				netFlow := packet.Packet.NetworkLayer().NetworkFlow()
				src, _ := netFlow.Endpoints()
				ipnet := net.IPNet(cidr)
				ip := net.IP(src.Raw())
				if ipnet.Contains(ip) {
					fmt.Printf("Allowing because packet contains %s", ipnet, ip)
					packet.SetVerdict(netfilter.NF_ACCEPT)
				}
			}

		}
	}
}
