package main

import (
        "fmt"
        "github.com/openshift/geard/pkg/go-netfilter-queue"
        "os"
	"net"
)

type Cidr IPNet

func UnmarshalJSON(ip *Cidr,bytes byte[]) (err) {	
	data, err := json.Unmarshal(bytes)
	if err==nil { return nil,err }
	ip,ipnet,err:=errnet.ParseCIDR(data)
	return ipnet,err
}

func consulKey(serv key) (chan string){
 	ch := make(chan string)
 	go func(serv string,tags string){
 		opts := consulapi.QueryOptions{}
 		for {
 			client,err := consulapi.NewClient(consulapi.DefaultConfig()) 		        
 			if err == nil {
 				kv := client.KV()
 				for {
 					value,queryinfo,err2 := kv.Get(serv,&opts)
					cidrs = make([]Cidr,0,0)
					err3 := json.Unmarshal(value,&cidrs)
 					if err2== nil && err3==nil {
 						opts.WaitIndex = queryinfo.LastIndex
 						ch <- cidrs
 					} else if err2==nil
					{
						opts.WaitIndex = queryinfo.LastIndex	
						fmt.Printf("Could not parse %s,(%s)",value,err)					
					}
 				}
 			} else {
 				fmt.Printf("Could not connect to consul %s",err)
 				time.Sleep(3000 * time.Millisecond)
 			}
 		}
 	}(serv)
 	return ch
}

func main() {
        var err error
	
	allow := consulKeys("allow")
        nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
        if err != nil {
                fmt.Println(err)
                os.Exit(1)
        }
        defer nfq.Close()
        packets := nfq.GetPackets()
	cidrs:= make([]Cidr,0,0)

        for true {
                select {
		case cidrs = <- allow:
                case p := <- packets:
                        // fmt.Println(p.Packet)
                        for idx, cidr := range cidrs {
				netFlow := packet.NetworkLayer().NetworkFlow()
				src, dst := netFlow.Endpoints()
				if(cidr.Contains(dst))
				{ 
					p.SetVerdict(netfilter.NF_ACCEPT)
				}
			}

                }
        }
}
