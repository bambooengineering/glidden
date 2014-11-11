package main

import (
	"flag"
	"strings"
	"encoding/json"
	"github.com/armon/consul-api"
)

var ip = flag.String("allow", "10.0.0.0/8,127.0.0.1/24", "allow cidr")

func main(){
	client, _ := consulapi.NewClient(consulapi.DefaultConfig())
	kv := client.KV()
	data, err:=json.Marshal(strings.Split(*ip,","))
	p := &consulapi.KVPair{Key: "allow", Value: data}
	_, err2 := kv.Put(p, nil)
	if err2 != nil {
		panic(err)
	}
}
