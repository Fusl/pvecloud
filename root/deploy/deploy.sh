#!/usr/bin/env bash

basedir=$(dirname "${0}")
cd "${basedir}"

config_template="debian-9"
config_name="$(shuf -n 1 names/left)-$(shuf -n 1 names/right)"
config_memory="512"
config_disksize="0"
config_mac="$(printf '52:54:00:%02X:%02X:%02X\n' $[RANDOM%256] $[RANDOM%256] $[RANDOM%256] | tr '[:upper:]' '[:lower:]')"
config_bridge="vmbr0"
config_id="100"
config_uuid="$(cat /proc/sys/kernel/random/uuid)"
config_sshkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFSBkWq9w1UOT4m90XtI0P1o/NUpj8VhQPSezUsIQSgx fusl@meo.ws"
config_cores="$(numactl -H | grep -E '^node [0-9]+ cpus: ' | cut -d' ' -f4- | awk '{print NF}' | sort -nk1 | head -n 1 || echo -n 1)"
config_sockets="$(numactl -H | grep -E '^node [0-9]+ cpus: ' | wc -l || echo -n 1)"
config_node="${HOSTNAME}"
config_pool="repl3"
config_tpool="repl3"
config_vtag=""
config_ip="auto"
config_gw=""
config_legacydisk="y"
config_ip6="auto"
config_gw6=""
config_asn=""
config_cpulimit=""
config_balloon=""

config_id=100
while test -f "/etc/pve/nodes/"*"/qemu-server/${config_id}.conf"; do
	config_id="$((${config_id}+1))"
done
#while test -f "/etc/pve/nodes/"*"/qemu-server/${config_id}.conf" || rbd info "${config_pool}/vm-${config_id}-cloudinit" 1>/dev/null 2>/dev/null; do
#	config_id="$((${config_id}+1))"
#done

function urlencode() {
	old_lc_collate="${LC_COLLATE}"
	LC_COLLATE="C"
	local length="${#1}"
	for (( i = 0; i < length; i++ )); do
		local c="${1:i:1}"
		case ${c} in
			[a-zA-Z0-9.~_-]) printf "$c" ;;
			*) printf '%%%02X' "'$c" ;;
		esac
	done
	LC_COLLATE="${old_lc_collate}"
}

function parseoption() {
	echo -n "${*}" | sed -r 's/^(--[a-z]+=|--[a-z]+$|-[a-z]=|-[a-z])//'
}

function printhelp() {
local ex_template=$(  printf "%50s" "[${config_template}]")
local ex_name=$(      printf "%50s" "[${config_name}]")
local ex_memory=$(    printf "%50s" "[${config_memory}]")
local ex_balloon=$(   printf "%50s" "[${config_balloon}]")
local ex_disksize=$(  printf "%50s" "[${config_disksize}]")
local ex_mac=$(       printf "%50s" "[${config_mac}]")
local ex_bridge=$(    printf "%50s" "[${config_bridge}]")
local ex_id=$(        printf "%50s" "[${config_id}]")
local ex_uuid=$(      printf "%50s" "[${config_uuid}]")
local ex_sshkey=$(    printf "%50s" "[${config_sshkey}]")
local ex_cores=$(     printf "%50s" "[${config_cores}]")
local ex_sockets=$(   printf "%50s" "[${config_sockets}]")
local ex_node=$(      printf "%50s" "[${config_node}]")
local ex_pool=$(      printf "%50s" "[${config_pool}]")
local ex_tpool=$(     printf "%50s" "[${config_tpool}]")
local ex_vtag=$(      printf "%50s" "[${config_vtag}]")
local ex_ip=$(        printf "%50s" "[${config_ip}]")
local ex_gw=$(        printf "%50s" "[${config_gw}]")
local ex_ip6=$(       printf "%50s" "[${config_ip6}]")
local ex_gw6=$(       printf "%50s" "[${config_gw6}]")
local ex_legacydisk=$(printf "%50s" "[${config_legacydisk}]")
local ex_asn=$(       printf "%50s" "[${config_asn}]")
local ex_cpulimit=$(  printf "%50s" "[${config_cpulimit}]")
cat << EOF
Usage: "${0}" [OPTIONS]
======================================================================
  -h, --help        Print this help text
  -t, --template    Template to use
                    ${ex_template}
  -n, --name        Hostname for this VM
                    ${ex_name}
  -m, --memory      Amount of memory in MB to give this VM
                    ${ex_memory}
      --balloon     Amount of minimum balloon allocation in MB
                    ${ex_balloon}
                    Balloon + memory can also be specified as
                    --memory balloon/limit (-m 1024/4096)
  -d, --disksize    Amount of disk size in GB to allocate for this VM
                    ${ex_disksize}
      --mac         Interface MAC address
                    ${ex_mac}
  -b, --bridge      Bridge for this VMs interface
                    ${ex_bridge}
  -i, --id          VM ID
                    ${ex_id}
  -u, --uuid        VM UUID
                    ${ex_uuid}
  -k, --sshkey      SSH key for cloud-init
                    ${ex_sshkey}
  -c, --cores       CPU cores
                    ${ex_cores}
  -s, --sockets     CPU sockets
                    ${ex_sockets}
      --node        PVE host node
                    ${ex_node}
  -p, --pool        Ceph RBD pool
                    ${ex_pool}
      --tpool       Ceph template RBD pool
                    ${ex_tpool}
      --vtag        VLAN Tag ID
                    ${ex_vtag}
      --ip          VM IPv4/subnet (example: 192.0.2.2/24)
                    "auto" to pick from config/ip4.txt
                    ${ex_ip}
      --gw          VM IPv4 Gateway (example: 192.0.2.1)
                    Automatically assigned when using "auto"
                    ${ex_gw}
      --ip6         VM IPv6/subnet (example: 2001:db8::/56)
                    "auto" to pick from config/ip6.txt
                    ${ex_ip6}
      --gw6         VM IPv6 Gateway (example: fe80::1)
                    Automatically assigned when using "auto"
                    ${ex_gw6}
      --legacydisk  Use legacy disk format (vm-100-disk-0) instead of
                    cloud disk UUID format (vm-0-<disk uuid>)
                    ${ex_legacydisk}
  -a, --as, --asn   Allow BGP sessions from this VM with this AS
                    ${ex_asn}
      --cpulimit    CPU limit (1 = 1 core, up to 128)
                    ${ex_cpulimit}
EOF
}

function parseoptions() {
	while [ "x${#}" != "x0" ]; do
		local value=""
		case "${1}" in
			-h*|--help|--help=*)
				printhelp
				exit 0
			;;
			-t*|--template|--template=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_template="${value}"
			;;
			-n*|--name|--name=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_name="${value}"
			;;
			-m*|--memory|--memory=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_memory="${value}"
			;;
			--balloon|--balloon=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_balloon="${value}"
			;;
			-d*|--disksize|--disksize=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_disksize="${value}"
			;;
			--mac|--mac=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_mac="${value}"
			;;
			-b*|--bridge|--bridge=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_bridge="${value}"
			;;
			-i*|--id|--id=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_id="${value}"
			;;
			-u*|--uuid|--uuid=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_uuid="${value}"
			;;
			-k*|--sshkey|--sshkey=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_sshkey="${value}"
			;;
			-c*|--cores|--cores=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_cores="${value}"
			;;
			-s*|--sockets|--sockets=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_sockets="${value}"
			;;
			--node|--node=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_node="${value}"
			;;
			-p*|--pool|--pool=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_pool="${value}"
			;;
			--tpool|--tpool=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_tpool="${value}"
			;;
			--vtag|--vtag=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_vtag="${value}"
			;;
			--ip|--ip=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_ip="${value}"
			;;
			--gw|--gw=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_gw="${value}"
			;;
			--ip6|--ip6=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_ip6="${value}"
			;;
			--gw6|--gw6=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_gw6="${value}"
			;;
			--legacydisk|--legacydisk=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_legacydisk="${value}"
			;;
			-a*|--as|--as=*|--asn|--asn=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_asn="${value}"
			;;
			--cpulimit|--cpulimit=*)
				value=$(parseoption "${1}")
				[ "x${value}" == "x${1}" ] && value=""
				[ "x${value}" == "x" ] && [ "x${2:0:1}" != "x-" ] && value="${2}" && shift
				config_cpulimit="${value}"
			;;
			*)
				printhelp
				exit 1
			;;
		esac
		shift
	done
}

function is_int() {
	case "${*}" in
		''|*[!0-9]*) return 1 ;;
		*) return 0 ;;
	esac
}
function is_between() {
	if ! is_int "${1}" || test "${1}" "-le" "${2}" || test "${1}" "-ge" "${3}"; then
		return 1
	fi
	return 0
}
parseoptions "${@}"

if echo "${config_memory}" | fgrep -q /; then
	config_balloon="${config_memory%/*}"
	config_memory="${config_memory#*/}"
	if test "${config_balloon}" -gt "${config_memory}"; then
		config_balloon_tmp="${config_memory}"
		config_memory="${config_balloon}"
		config_balloon="${config_balloon_tmp}"
	fi
fi

test -r "configs/${config_template}.conf" || { echo "Template file configs/${config_template}.conf not found"; printhelp; exit 2; }
test -f "/etc/pve/nodes/"*"/qemu-server/${config_id}.conf" && { echo "Configuration file for ID ${config_id} exists already"; printhelp; exit 3; }
rbd info "${config_tpool}/template-${config_template}" 1>/dev/null 2>/dev/null || { echo "Template image ${config_tpool}/template-${config_template} not found"; printhelp; exit 4; }
is_int "${config_memory}" || { echo "memory=${config_memory} is not numeric"; printhelp; exit 5; }
is_int "${config_disksize}" || { echo "disk=${config_disksize} is not numeric"; printhelp; exit 6; }
is_int "${config_id}" || { echo "id=${config_id} is not numeric"; printhelp; exit 7; }
is_int "${config_cores}" || { echo "cores=${config_cores} is not numeric"; printhelp; exit 8; }
is_int "${config_sockets}" || { echo "sockets=${config_sockets} is not numeric"; printhelp; exit 9; }
test -z "${config_vtag}" || is_int "${config_vtag}" || { echo "vtag=${config_vtag} is not numeric"; printhelp; exit 10; }
test -z "${config_ip}" || test "${config_ip}" == "auto" || echo "${config_ip}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]{1,2}$' || { echo "ip=${config_ip} is of invalid format"; printhelp; exit 11; }
test -z "${config_gw}" || echo "${config_gw}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || { echo "gw=${config_gw} is of invalid format"; printhelp; exit 12; }
test -z "${config_asn}" || is_int "${config_asn}" || { echo "asn=${config_asn} is invalid"; printhelp; exit 13; }
test -z "${config_cpulimit}" || is_int "${config_cpulimit}" || { echo "cpulimit=${config_cpulimit} is invalid"; printhelp; exit 14; }
test -z "${config_balloon}" || is_int "${config_balloon}" || { echo "balloon=${config_balloon} is not numeric"; printhelp; exit 15; }

config_sshkey=$(urlencode "${config_sshkey}")

if test "${config_legacydisk}" == "n"; then
	rootdiskvmid="0"
	rootdiskuuid=$(cat /proc/sys/kernel/random/uuid)
else
	rootdiskvmid="${config_id}"
	rootdiskuuid="disk-0"
fi

if test "${config_ip}" == "auto" || test "${config_ip6}" == "auto"; then
	used_ips=$(grep -E '^ipconfig[0-9]+: ' /etc/pve/nodes/*/qemu-server/*.conf | grep -oE 'ip6?=[^,$]+' | cut -d= -f2)
fi

if test "${config_ip}" == "auto"; then
	all_ip4=$(cat config/ip4.txt)
	avail_ip4=$(
		echo "${all_ip4}" | shuf | while read cand_ip4 cand_gw4 _; do
			cand_ip4_addr=$(echo "${cand_ip4}" | cut -d/ -f1)
			if ! echo "${used_ips}" | cut -d/ -f1 | grep -Fxq "${cand_ip4_addr}"; then
				echo "${cand_ip4} ${cand_gw4}"
				break
			fi
		done
	)
	if test -z "${avail_ip4}"; then
		echo "No free IPv4 address available in pool; Use --ip and --gw to force use of an already in-use IPv4 address"
		exit 16
	fi
	echo "Found free IPv4 address: ${avail_ip4}"
	config_ip="${avail_ip4%% *}"
	config_gw="${avail_ip4##* }"
fi

if test "${config_ip6}" == "auto"; then
	all_ip6=$(cat config/ip6.txt)
	avail_ip6=$(
		echo "${all_ip6}" | shuf | while read cand_ip6 cand_gw6 _; do
			cand_ip6_addr=$(echo "${cand_ip6}" | cut -d/ -f1)
			if ! echo "${used_ips}" | grep -Fxq "${cand_ip6_addr}"; then
				echo "${cand_ip6} ${cand_gw6}"
				break
			fi
		done
	)
	if test -z "${avail_ip6}"; then
		echo "No free IPv6 address available in pool; Use --ip and --gw to force use of an already in-use IPv6 address"
		exit 16
	fi
	echo "Found free IPv6 address: ${avail_ip6}"
	config_ip6="${avail_ip6%% *}"
	config_gw6="${avail_ip6##* }"
fi

config=$(DISKSIZE="${config_disksize}" MEMORY="${config_memory}" NAME="${config_name}" MAC="${config_mac}" BRIDGE="${config_bridge}" ID="${config_id}" UUID="${config_uuid}" SSHKEY="${config_sshkey}" CORES="${config_cores}" SOCKETS="${config_sockets}" POOL="${config_pool}" VTAG="${config_vtag}" IP="${config_ip}" GW="${config_gw}" IP6="${config_ip6}" GW6="${config_gw6}" ROOTDISKVMID="${rootdiskvmid}" ROOTDISKUUID="${rootdiskuuid}" ASN="${config_asn}" CPULIMIT="${config_cpulimit}" BALLOON="${config_balloon}" bin/mo "configs/${config_template}.conf" | grep -vE '^$' | sort -u)

#echo "${config}"
#exit 0

echo "Creating VM with id ${config_id} disk uuid ${rootdiskuuid} ip4 ${config_ip%%/*} (${config_ip} ${config_gw}) ip6 ${config_ip6%%/*} (${config_ip6} ${config_gw6})"

echo "${config}" > "/etc/pve/nodes/${config_node}/qemu-server/${config_id}.conf" || {
	echo "Failed to write PVE config /etc/pve/nodes/${config_node}/qemu-server/${config_id}.conf"
	exit 128
}

snapshot_name=$(rbd snap ls "${config_tpool}/template-${config_template}" --format json | jq -Mcr 'if length > 0 then sort_by (.id) | reverse | .[0].name else empty end')

if test "${snapshot_name}" == ""; then
	rbd cp "${config_tpool}/template-${config_template}" "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}" || {
		echo "Failed to copy template image (${config_tpool}/template-${config_template} -> ${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid})"
		rbd rm "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}"
		rm "/etc/pve/nodes/${config_node}/qemu-server/${config_id}.conf"
		exit 128
	}
else
	rbd clone "${config_tpool}/template-${config_template}@${snapshot_name}" "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}" || {
		echo "Failed to clone template image (${config_tpool}/template-${config_template} -> ${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid})"
		rbd rm "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}"
		rm "/etc/pve/nodes/${config_node}/qemu-server/${config_id}.conf"
		exit 128
	}
fi

if test "${config_disksize}" != "0"; then
	rbd resize -s "${config_disksize}G" "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}" || {
		echo "Failed to resize disk ${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}"
		rbd rm "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}"
		rm "/etc/pve/nodes/${config_node}/qemu-server/${config_id}.conf"
		exit 128
	}
fi

#rbd create -s 5M "${config_pool}/vm-${config_id}-cloudinit" || {
#	echo "Failed to create cloud-init drive ${config_pool}/vm-${config_id}-cloudinit"
#	rbd rm "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}"
#	rbd rm "${config_pool}/vm-${config_id}-cloudinit"
#	rm "/etc/pve/nodes/${config_node}/qemu-server/${config_id}.conf"
#	exit 128
#}

ssh "root@${config_node}" qm start "${config_id}" || {
	echo "Failed to start VM ${config_id}"
	rbd rm "${config_pool}/vm-${rootdiskvmid}-${rootdiskuuid}"
	#rbd rm "${config_pool}/vm-${config_id}-cloudinit"
	rm "/etc/pve/nodes/${config_node}/qemu-server/${config_id}.conf"
	exit 128
}

echo "VM deployed successfully"

echo ssh "root@${config_node}" socat "UNIX-CONNECT:/var/run/qemu-server/${config_id}.serial0" STDIO
