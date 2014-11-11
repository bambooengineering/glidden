# Glidden, consul iptables filter

Uses nfqueue and consul to filter packets dynamically

## To use, run

Use 
````bash
glidden-client -set "10.0.0.0/8,127.0.0.1/24"
sudo iptables -I INPUT -i eth0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
sudo glidden
````
## Other information

This package uses the netfilter library from https://github.com/OneOfOne/go-nfqueue under the apache license

Glidden was the inventor of barbed wire