#!/usr/bin/env bash

#################################
#  CLEAR OUT EXISTING FIREAWLL  #
#################################

# First we need to remove all ip(6)tables rules so we clear also ipset pointers
for bin in iptables ip6tables; do
	for table in raw mangle filter; do
		"${bin}" -t "${table}" -F
		"${bin}" -t "${table}" -X
		"${bin}" -t "${table}" -Z
	done
done

bin=ebtables
for table in filter nat broute; do
	"${bin}" -t "${table}" -F
	"${bin}" -t "${table}" -X
	"${bin}" -t "${table}" -Z
done

# next we clear all ipset chains
#ipset destroy aclblock
#ipset destroy aclblock6
#ipset destroy bogons
#ipset destroy smtp
#ipset destroy smtp6
ipset destroy

# create all necessary ipset chains for later use
ipset create aclblock hash:ip
ipset create aclblock6 hash:ip family inet6
ipset create bogons hash:net
ipset create smtp hash:ip
ipset create smtp6 hash:ip family inet6

ebtables -t nat -A PREROUTING -i tap+ --logical-in vmbr0 -p ARP --arp-op Request -j arpreply --arpreply-mac 11:11:11:11:11:11
ebtables -t nat -A PREROUTING -i tap+ --logical-in vmbr0 -j DROP

# prepare iptables raw target PREROUTING chain for filtering
iptables -t raw -N from_vms
iptables -t mangle -N to_vms
iptables -t raw -A PREROUTING -i tap+ -j from_vms
#iptables -t raw -A PREROUTING -i tap+ -j LOG --log-prefix "iptables init 1: "
iptables -t raw -A PREROUTING -i tap+ -j DROP
iptables -t mangle -A POSTROUTING -o tap+ -j to_vms
#iptables -t mangle -A POSTROUTING -o tap+ -j LOG --log-prefix "iptables init 2: "
iptables -t mangle -A POSTROUTING -o tap+ -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400

# prepare ip6tables raw target PREROUTING chain for filtering
ip6tables -t raw -N from_vms
ip6tables -t mangle -N to_vms
ip6tables -t raw -A PREROUTING -i tap+ -j from_vms
#ip6tables -t raw -A PREROUTING -i tap+ -j LOG --log-prefix "ip6tables init 1: "
ip6tables -t raw -A PREROUTING -i tap+ -j DROP
ip6tables -t mangle -A POSTROUTING -o tap+ -j to_vms
#ip6tables -t mangle -A POSTROUTING -o tap+ -j LOG --log-prefix "ip6tables init 2: "
ip6tables -t mangle -A POSTROUTING -o tap+ -j DROP
ip6tables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400


#################################
#  FILL IPSET CHAINS WITH DATA  #
#################################

for bogonnet in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
	ipset add bogons "$bogonnet"
done

for interface in /sys/class/net/tap*i*; do
	interface=$(echo "${interface}" | cut -d/ -f5)
	INTERFACE="${interface}" ACTION="add" /opt/scripts/pvecloudfw.sh
done
