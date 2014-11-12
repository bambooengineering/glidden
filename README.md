# Glidden, consul/iptables interface

Uses nfqueue and consul to dynamically filter connections. 

NFQueue is an Linux/IPTables feature which allows the decision on which packets to be accepted to be made by userspace applications. In glidden, we subscribe to a consul key, in which we expect to find a set of CIDRs. If the packets we recieve from the kernel falls into one of these CIDRs, we allow it though. In glidden, we only inspect the first packet in a connection, so as to reduce performance requirements- if the first packet is allowed through, all the following packets will be allowed through (using the IPTables conntrack feature) You can at any time change the set of allowed CIDRs, and through the consul subscription, glidden will allow and disallow packets as you please. 

## To use, run

Use 
````bash
glidden-client -allow="10.0.0.0/8,127.0.0.1/24"
sudo iptables -I INPUT -i eth0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
sudo glidden
````
## Other information

This package uses the netfilter library from https://github.com/OneOfOne/go-nfqueue under the apache license.

Glidden was the inventor of barbed wire.