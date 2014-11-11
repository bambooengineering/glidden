# Glidden, consul iptables filter

Uses nfqueue and consul to filter packets dynamically

## To use, run

Use 

`glidden-client -set "10.0.0.0/8,127.0.0.1/24"`
`sudo iptables -I INPUT -i eth0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0`
`sudo glidden`
