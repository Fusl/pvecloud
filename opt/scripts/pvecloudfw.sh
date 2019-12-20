#!/usr/bin/env bash

set -eu

urldecode() {
	local url_encoded="${1//+/ }"
	printf '%b' "${url_encoded//%/\\x}"
}

if ! echo "${INTERFACE}" | grep -qE '^tap([0-9]+)i([0-9]+)$'; then
	exit 0
fi

vmid_vmif=$(echo "${INTERFACE}" | sed -r 's|^tap([0-9]+)i([0-9]+)$|\1 \2|')

vmid=$(echo "${vmid_vmif}" | cut -d' ' -f1)
vmif=$(echo "${vmid_vmif}" | cut -d' ' -f2)

XINTERFACE="tap${vmid}i+"

if test "${vmid}" == "" || test "${vmif}" != "0"; then
	exit 0
fi

if ! test -f "/etc/pve/nodes/"*"/qemu-server/${vmid}.conf"; then
	exit 0
fi

config=$(cat "/etc/pve/nodes/"*"/qemu-server/${vmid}.conf" | sed '/^$/q')
if echo "${config}" | grep -qE '^#legacy$'; then
	exit 0
fi

link_local() {
	local IFS=':'
	set $1
	unset IFS
	echo "fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6"
}

add() {
	ipset list "${vmid}v4" 1> /dev/null 2> /dev/null && remove refresh
	ipconfig=$(echo "${config}" | grep -E '^ipconfig[0-9]+: ' | cut -d' ' -f2 | tr ',=' '\n ' || true)
	ipconfig_ips=$(echo "${ipconfig}" | grep -E '^ip[46]? ' | cut -d' ' -f2 || true)
	comment_ips=$(echo "${config}" | grep -E '^#ip[46]? ' | cut -d' ' -f2 || true)
	comment_ips=$(urldecode "${comment_ips}")
	#md_ip_port=$(bash -c 'RANDOM='"${seed}"'; echo 127.$((${RANDOM}%256)).$((${RANDOM}%256)).$((${RANDOM}%256)) $((1024+((${RANDOM}+${RANDOM}+${RANDOM}+${RANDOM}+${RANDOM})%64512)))')
	ips=$(
		(
			echo "${ipconfig_ips}"
			echo "${comment_ips}"
		) | grep -vE '^$' | sort -t/ -nk2,2 | sort -u -t/ -k1,1 || true
	)
	gw6=$(
		echo "${ipconfig}" | grep -E '^gw6 ' | cut -d' ' -f2 | sort -u || true
	)
	macs=$(echo "${config}" | grep -E '^net[0-9]+: ' | cut -d' ' -f2 | cut -d, -f1 | cut -d= -f2 || true)
	firstmac=$(echo "${macs}" | head -n 1)
	echo -n "Waiting for interface activation"
	while true; do
		test -d "/sys/class/net/${INTERFACE}/" || exit 0
		operstate=$(cat "/sys/class/net/${INTERFACE}/operstate")
		test "${operstate}" == "unknown" && break
		echo -n .
		sleep "0.${RANDOM}"
	done
	echo ""
	if type jq 1> /dev/null 2> /dev/null; then
		echo -n "Waiting for VM status to be 'running true'"
		while true; do
			test -d "/sys/class/net/${INTERFACE}/" || exit 0
			if test -S "/run/qemu-server/${vmid}.qmp"; then
				vmstate=$((echo '{"execute":"qmp_capabilities"}'; echo '{"execute":"query-status"}') | socat STDIO "UNIX:/run/qemu-server/${vmid}.qmp" | tail -n1 | jq -rMc '(.return.status | tostring) + " " + (.return.running | tostring)')
				test "${vmstate}" == "running true" && break
			fi
			echo -n .
			sleep "0.${RANDOM}"
		done
		echo ""
	fi
	pid=$(cat "/run/qemu-server/${vmid}.pid")
	pgrep -f '^vhost-'"${pid}"'$' | xargs -r renice -n -20 -p
	echo 0 | tee "/proc/sys/net/ipv6/conf/tap${vmid}i"*"/disable_ipv6" > /dev/null
	ebtables -t broute -N "from_${vmid}" -P ACCEPT
	for mac in ${macs}; do
		ebtables -t broute -A BROUTING -i "${XINTERFACE}" --logical-in vmbr0 -s "${mac}" -j "from_${vmid}"
	done

	iptables -t raw -N "from_${vmid}"
	iptables -t mangle -N "to_${vmid}"
	iptables -t raw -A from_vms -i "${XINTERFACE}" -j "from_${vmid}"
	iptables -t mangle -A to_vms -o "${XINTERFACE}" -j "to_${vmid}"

	ip6tables -t raw -N "from_${vmid}"
	ip6tables -t mangle -N "to_${vmid}"
	ip6tables -t raw -A from_vms -i "${XINTERFACE}" -j "from_${vmid}"
	ip6tables -t mangle -A to_vms -o "${XINTERFACE}" -j "to_${vmid}"

	mysrcip4=$(cat /usr/local/etc/bird.conf | grep -E '^define ip4 = [0-9\.]+;$' | cut -d' ' -f4 | cut -d';' -f1 || ip r g 255.255.255.255 2> /dev/null | grep -oE 'src [0-9\.]{7,15}' | tr -s ' ' | cut -d' ' -f2)
	mysrcip6=$(cat /usr/local/etc/bird.conf | grep -E '^define ip6 = [0-9a-f:]+;$' | cut -d' ' -f4 | cut -d';' -f1 || ip r g 2000:: 2> /dev/null | grep -oE 'src [a-f0-9:]+' | tr -s ' ' | cut -d' ' -f2)
	firstip=$(echo "${ips}" | head -n 1)
	if echo "${firstip}" | fgrep -q .; then
		defgw=$(echo "${firstip}" | cut -d. -f1-3).1
	fi
	ipset create "${vmid}v4" hash:net
	ipset create "${vmid}v6" hash:net family inet6
	#ip address flush dev "tap${vmid}i0"
	ip link set dev "tap${vmid}i0" address 04:08:15:16:23:42
	for ip in ${ips}; do
		#ip=$(urldecode "${ip}")
		prefix=$(echo "${ip}" | cut -d/ -f2)
		ip=$(echo "${ip}" | cut -d/ -f1)
		if echo "${ip}" | fgrep -q .; then
			mysrcip="${mysrcip4}"
			ipset add "${vmid}v4" "${ip}/32"
			ebtables -t broute -A "from_${vmid}" -p IPv4 --ip-source "${ip}" -j redirect --redirect-target DROP
			ip neighbour replace "${ip}" dev "${INTERFACE}" lladdr "${firstmac}" nud permanent
			ip route replace "${ip}" dev "${INTERFACE}" src "${mysrcip}" pref high scope link
			ip address add "169.254.169.254/32" peer "${ip}" dev "${INTERFACE}" scope link || true
		elif echo "${ip}" | fgrep -q :; then
			mysrcip="${mysrcip6}"
			ipset add "${vmid}v6" "${ip}/56"
			ebtables -t broute -A "from_${vmid}" -p IPv6 --ip6-source "${ip}/${prefix}" -j redirect --redirect-target DROP
			ip route replace "${ip}" dev "${INTERFACE}" src "${mysrcip}" pref high
			ip address del "fe80::1/128" dev "${INTERFACE}" scope link || true
			ip address add "fe80::1/128" peer "${ip}" dev "${INTERFACE}" scope link || true
		fi
	done
	for gw in ${gw6}; do
		test "${gw}" == "fe80::1" && continue
		ip address add "${gw}/56" dev "tap${vmid}i0" scope link || true
	done
	for interface in "/sys/class/net/tap${vmid}i"*"/address"; do
		interface=$(echo "${interface}" | cut -d/ -f5)
		mac=$(cat "/sys/class/net/${interface}/address")
		lla=$(link_local "${mac}")
		ip address add "${lla}/64" dev "${interface}" scope link || true
		ip address add "fe80::1/128" dev "${interface}" scope link || true
		ip address add "169.254.169.254/32" dev "${interface}" scope link || true
		ip address add "fc00::179/128" dev "${interface}" scope link || true
	done

	#iptables -t raw -A "from_${vmid}" -m set ! --match-set "${vmid}v4" src -j LOG --log-prefix "iptables 1: "
	iptables -t raw -A "from_${vmid}" -m set ! --match-set "${vmid}v4" src -j DROP
	iptables -t raw -A "from_${vmid}" -d 169.254.169.254 -p tcp --dport 179 -j ACCEPT
	#iptables -t raw -A "from_${vmid}" -m set --match-set bogons dst -j LOG --log-prefix "iptables 2: "
	iptables -t raw -A "from_${vmid}" -m set --match-set bogons dst -j DROP
	iptables -t raw -A "from_${vmid}" -j ACCEPT

	#iptables -t mangle -A "to_${vmid}" -m set ! --match-set "${vmid}v4" dst -j LOG --log-prefix "iptables 3: "
	iptables -t mangle -A "to_${vmid}" -m set ! --match-set "${vmid}v4" dst -j DROP
	iptables -t mangle -A "to_${vmid}" -s 169.254.169.254 -p tcp --sport 179 -j ACCEPT
	#iptables -t mangle -A "to_${vmid}" -m set --match-set bogons src -j LOG --log-prefix "iptables 4: "
	iptables -t mangle -A "to_${vmid}" -m set --match-set bogons src -j DROP
	iptables -t mangle -A "to_${vmid}" -j ACCEPT

	for mac in ${macs}; do
		lla=$(link_local "${mac}")
		ebtables -t broute -A "from_${vmid}" -p IPv6 --ip6-source "${lla}/128" -j redirect --redirect-target DROP
		ip6tables -t raw -A "from_${vmid}" -s "${lla}/128" -p icmpv6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
		ip6tables -t raw -A "from_${vmid}" -s "${lla}/128" -p icmpv6 --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT
		ip6tables -t mangle -A "to_${vmid}" -d "${lla}/128" -p icmpv6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
		ip6tables -t mangle -A "to_${vmid}" -d "${lla}/128" -p icmpv6 --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT
		ip6tables -t mangle -A "to_${vmid}" -d "ff02::1:ff00:0/104" -p icmpv6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
		ip6tables -t mangle -A "to_${vmid}" -d "ff02::1:ff00:0/104" -p icmpv6 --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT
	done

	#ip6tables -t raw -A "from_${vmid}" -m set ! --match-set "${vmid}v6" src -j LOG --log-prefix "ip6tables 1: "
	ip6tables -t raw -A "from_${vmid}" -m set ! --match-set "${vmid}v6" src -j DROP
	ip6tables -t raw -A "from_${vmid}" -d 2000::/3 -j ACCEPT
	ip6tables -t raw -A "from_${vmid}" -d fc00::179 -p tcp --dport 179 -j ACCEPT
	ip6tables -t raw -A "from_${vmid}" -p icmpv6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
	ip6tables -t raw -A "from_${vmid}" -p icmpv6 --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT

	#ip6tables -t mangle -A "to_${vmid}" -m set ! --match-set "${vmid}v6" dst -j LOG --log-prefix "ip6tables 2: "
	ip6tables -t mangle -A "to_${vmid}" -m set ! --match-set "${vmid}v6" dst -j DROP
	ip6tables -t mangle -A "to_${vmid}" -s 2000::/3 -j ACCEPT
	ip6tables -t mangle -A "to_${vmid}" -s fc00::179 -p tcp --sport 179 -j ACCEPT
	ip6tables -t mangle -A "to_${vmid}" -p icmpv6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
	ip6tables -t mangle -A "to_${vmid}" -p icmpv6 --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT

	asn=$(echo "${config}" | grep -E '^#[Aa][Ss] ?' | sed -r 's|^#[Aa][Ss] ?([0-9]+)$|\1|' | head -n 1 || true)
	if test -n "${asn}"; then
		prefixes=$(whois -h whois.radb.net -K -i origin "AS${asn}" | grep -E 'route6?:' | awk '{print $2}' | tr '[:upper:]' '[:lower:]' | grep -E '^[a-z0-9:\.]+/[0-9]{1,3}$' | sort -u || true)
		ip4_prefixes_list=$(echo "${prefixes}" | fgrep . || true)
		ip6_prefixes_list=$(echo "${prefixes}" | fgrep : || true)
		ip4_prefixes_array=$(echo "${ip4_prefixes_list}" | tr '\n' ' ' | sed 's/ $//')
		ip6_prefixes_array=$(echo "${ip6_prefixes_list}" | tr '\n' ' ' | sed 's/ $//')
		ip4_prefixes=$(echo "${ip4_prefixes_list}" | grep -vE '^$' | awk -F/ '$2 <= 24 {print $1"/"$2"{"$2","$2"}"}' | tr '\n' ',' | sed 's/,$//' || true)
		ip6_prefixes=$(echo "${ip6_prefixes_list}" | grep -vE '^$' | awk -F/ '$2 <= 48 {print $1"/"$2"{"$2","$2"}"}' | tr '\n' ',' | sed 's/,$//' || true)
		ip4_filter="ipv4 { import none; };"
		ip4_num=$(($(echo "${ip4_prefixes_list}" | wc -l)+10))
		ip6_num=$(($(echo "${ip6_prefixes_list}" | wc -l)+10))
		rrclient=""
		pathfilter="bgp_path.len = 1 && bgp_path.last = ${asn}"
		if test "${asn}" == "204136"; then
			rrclient="rr client;"
			pathfilter="bgp_path.len = 0"
		fi
		if test -n "${ip4_prefixes}"; then
			ip4_filter="ipv4 { import limit ${ip4_num} action restart; import filter AS${asn}; };"
		fi
		ip6_filter="ipv6 { import none; };"
		if test -n "${ip6_prefixes}"; then
			ip6_filter="ipv6 { import limit ${ip6_num} action restart; import filter AS${asn}; };"
		fi
		rrclient=""
		for ip4_prefix in ${ip4_prefixes_array}; do
			ipset add "${vmid}v4" "${ip4_prefix}"
			ebtables -t broute -A "from_${vmid}" -p IPv4 --ip-source "${ip4_prefix}" -j redirect --redirect-target DROP
		done
		for ip6_prefix in ${ip6_prefixes_array}; do
			ipset add "${vmid}v6" "${ip6_prefix}"
			ebtables -t broute -A "from_${vmid}" -p IPv6 --ip6-source "${ip6_prefix}" -j redirect --redirect-target DROP
		done
		mkdir -p /run/bird/
		(
			echo "filter AS${asn} {"
			if test -n "${ip4_prefixes}"; then
				echo "if (net ~ [${ip4_prefixes}] && ${pathfilter}) then accept;"
			fi
			if test -n "${ip6_prefixes}"; then
				echo "if (net ~ [${ip6_prefixes}] && ${pathfilter}) then accept;"
			fi
			echo "reject;"
			echo "};"
		) > "/run/bird/AS${asn}.conf.$$" && mv "/run/bird/AS${asn}.conf.$$" "/run/bird/AS${asn}.conf"
		(
			num=0
			for ip in ${ips}; do
				prefix=$(echo "${ip}" | cut -d/ -f2)
				ip=$(echo "${ip}" | cut -d/ -f1)
				echo "protocol bgp vm${vmid}_${num} from vm {"
				echo "${rrclient}"
				#if echo "${ip}" | fgrep -q .; then
				#	echo "source address 169.254.169.254;"
				#elif echo "${ip}" | fgrep -q :; then
				#	echo "source address fe80::1;"
				#fi
				echo "neighbor ${ip} port 179 as ${asn};"
				echo "${ip4_filter}"
				echo "${ip6_filter}"
				echo "}"
				num="$((${num}+1))"
			done
		) > "/run/bird/VM${vmid}.conf.$$" && mv "/run/bird/VM${vmid}.conf.$$" "/run/bird/VM${vmid}.conf"
		pkill -HUP bird
	elif test -f "/run/bird/VM${vmid}.conf"; then
		rm "/run/bird/VM${vmid}.conf"
		pkill -HUP bird
	fi
}

remove() {
	if test -f "/run/bird/VM${vmid}.conf" && test "${1:-}" != "refresh"; then
		rm "/run/bird/VM${vmid}.conf"
		pkill -HUP bird
	fi
	macs=$(echo "${config}" | grep -E '^net[0-9]+: ' | cut -d' ' -f2 | cut -d, -f1 | cut -d= -f2 || true)
	firstmac=$(echo "${macs}" | head -n 1)
	for mac in ${macs}; do
		ebtables -t broute -D BROUTING -i "${XINTERFACE}" --logical-in vmbr0 -s "${mac}" -j "from_${vmid}" || true
	done
	ebtables -t broute -F "from_${vmid}"
	ebtables -t broute -X "from_${vmid}"
	iptables -t raw -D from_vms -i "${XINTERFACE}" -j "from_${vmid}"
	iptables -t raw -F "from_${vmid}"
	iptables -t raw -X "from_${vmid}"
	iptables -t mangle -D to_vms -o "${XINTERFACE}" -j "to_${vmid}"
	iptables -t mangle -F "to_${vmid}"
	iptables -t mangle -X "to_${vmid}"
	ip6tables -t raw -D from_vms -i "${XINTERFACE}" -j "from_${vmid}"
	ip6tables -t raw -F "from_${vmid}"
	ip6tables -t raw -X "from_${vmid}"
	ip6tables -t mangle -D to_vms -o "${XINTERFACE}" -j "to_${vmid}"
	ip6tables -t mangle -F "to_${vmid}"
	ip6tables -t mangle -X "to_${vmid}"
	ipset destroy "${vmid}v4"
	ipset destroy "${vmid}v6"
}

case "${ACTION}" in
	add) add ;;
	remove) remove ;;
	*) false ;;
esac

exit 0
