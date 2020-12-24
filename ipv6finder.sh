#!/bin/bash
#__________________________________________________________
# Author:     phillips321 contact through phillips321.co.uk
# License:    CC BY-SA 3.0
# Use:        ipv6 finder
# Released:   www.phillips321.co.uk
  version=0.8
# Dependencies:
#	arp-scan, sudo
# ChangeLog
#   v0.8    Dropped MacOS support, added support for older Linux, removed ifconfig dependency, cleaned up
#   v0.7    Incremented version numbers properly - whoops!
#   v0.6    Added bug where arp-scan comes back with Duplicates (DUP)
#   v0.5    Checks if there is a local Global IPv6 Address
#   v0.4    Added Global host discovery
# ToDo:
#	use MAC address as unique key

f_main(){
    OwnIpv6=$(ip addr show dev en0 | grep 'inet6' | grep 'fe80' | head -n1 | cut -d" " -f2 | cut -d"/" -f1)

    #ipv6 neighbor discovery
    echo -n "[+]Do ipv6 neighbor discovery. "
    NdpNeighbours=$(ndp -an | grep "%"${interface}| cut -d" " -f1 | sort -u)
    echo "Done"

    #Ping multicast address for local neighbours and store as LinkLocalNeighbours
    echo -n "[+]Pinging (ff02::1) multicast for nodes on link local. "
    LinkLocalNeighbours=$(ping6 -c 3 -I ${interface} ff02::1 | grep icmp_seq | cut -d" " -f4 | cut -d"," -f 1 | sort -u)
    echo "Done"

    #Ping multicast address for router neighbours and store as RouterLocalNeighbours
    echo -n "[+]Pinging (ff02::2) multicast for routers. "
    RouterLocalNeighbours=$(ping6 -c 3 -I ${interface} ff02::2 | grep icmp_seq | cut -d" " -f4 | cut -d"," -f 1 | sort -u)
    echo "Done"

    #Ping multicast address for unique local neighbours and store as UlaNeighbours
    echo -n "[+]Pinging (ff02::1) multicast for nodes on Unique Local Interface. "
    UlaAddress=$(ip -6 addr | grep "inet6" | grep -v "::1" | grep -v "fe80"| grep -E "inet6\ f(c|d)" | grep -v "temporary" | grep "autoconf" | awk {'print $2'} | cut -d"/" -f1)
    if [ ! -z "${UlaAddress}" ]; then
        UlaNeighbours=$(ping6 -c 3 -S ${UlaAddress} -I ${interface} ff02::1 | grep "icmp_seq=0" | cut -d" " -f4 | cut -d"," -f 1 | sort -u )
        { for i in ${UlaNeighbours} ; do ping6 -c 1 -S ${UlaAddress} -I ${interface} $i ; done } &> /dev/null
    else
        UlaAddress=""; UlaNeighbours=""
    fi
    echo "Done"

    #Ping multicast address for global neighbours and store as GlobalNeighbours
    echo -n "[+]Pinging (ff02::1) multicast for nodes on Global Interface. "
    IPV6Address=$(ip -6 addr | grep "inet6" | grep -v "::1" | grep -v "fe80"| grep -Ev "inet6\ f(c|d)" | grep -v "temporary" | grep "autoconf" | awk {'print $2'} | cut -d"/" -f1)
    if [ ! -z "${IPV6Address}" ]; then
        GlobalNeighbours=$(ping6 -c 3 -S ${IPV6Address} -I ${interface} ff02::1 | grep "icmp_seq=0" | cut -d" " -f4 | cut -d"," -f 1 | sort -u )
        { for i in ${GlobalNeighbours} ; do ping6 -c 1 -S ${IPV6Address} -I ${interface} $i ; done } &> /dev/null
    else
        IPV6Address=""; GlobalNeighbours=""
    fi
    echo "Done"

#TODO replace arp-scan with arp (don't need root and more results, but still problems with parsing of results)
#    echo -n "[+]ArpScanning local IPv4. "
#    ArpScan=$(arp -an | grep -v "incomplete" | grep -v "permanent" | cut -d" " -f2,4)
#    echo "Done"

    echo -n "[+]ArpScanning local IPv4. (if you are not running as root, you will be prompted for your password by sudo) "
    ArpScan=$(sudo arp-scan -l -I ${interface} | grep -v packets | grep -v DUP | grep -v ${interface} | grep -v Starting | grep -v Ending | cut -f1,2)
    echo "Done"

    echo "---------------------------|-----------------------------------------|-------------------|-----------------|-------------------------------"
    printf "%26s %1s %39s %1s %17s %1s %15s %1s %9s (Hostname)\n" "IPv6 Link Local" "|" "IPv6 Global" "|" "MAC Address" "|" "IPv4 Address" "|" "Info"
    echo "---------------------------|-----------------------------------------|-------------------|-----------------|-------------------------------"
    for IPV6LL in ${NdpNeighbours}; do
        # Remove interface identifier (if any)
        IPV6LL=$(echo ${IPV6LL} | head -n1 | cut -d"%" -f1 | sed "s/:\$//g")
        IPV6LL_WITH_INTERFACE="${IPV6LL}%${interface}"

        #Get LinkLocal MAC from NDP table
        ShortMAC=$(ip -6 neigh show | grep ${IPV6LL} | awk {'print $5'} | sed 's/0\([0-9A-Fa-f]\)/\1/g')
        MediumMAC=$(ip -6 neigh show | grep ${IPV6LL} | awk {'print $5'})
        LongMAC=$(ip -6 neigh show | grep ${IPV6LL} | awk {'print $5'} | /usr/local/opt/gnu-sed/libexec/gnubin/sed 's/\b\([0-9A-Z]\)\b/0\1/g')
        if [ -z "${ShortMAC}" ] ; then ShortMAC=$(ip link show ${interface} | grep 'ether' | sed -e 's/.*ether \(..:..:..:..:..:..\).*/\1/' | sed 's/0\([0-9A-Fa-f]\)/\1/g'); fi
        if [ -z "${LongMAC}" ] ; then LongMAC=$(ip link show ${interface} | grep 'ether' | sed -e 's/.*ether \(..:..:..:..:..:..\).*/\1/'); fi

        #Use MAC to pair up with IPv4 address and global IPv6
        if [ ! -z "${LongMAC}" ]; then
            IPV4Address=$(echo "${ArpScan}" | grep "${LongMAC}" | head -n1 | cut -f1)
            IPV6G=""
            IPV6G=$(ip -6 neigh show | grep "${MediumMAC}" | grep -v fe80 | awk {'print $1'} | head -n1)
            if [ -z "${IPV6G}" ]; then
                IPV6G="NotFound"
                ip link show ${interface} | grep 'ether' | sed -e 's/.*ether \(..:..:..:..:..:..\).*/\1/' | grep -q ${LongMAC}
                if [ $? -eq 0 ]; then
                    IPV6G=$IPV6Address
                fi
            fi
        fi

        #IPv4 not found so might be you or not in subnet?
        if [ -z "${IPV4Address}" ]; then #Unable to find IPv4 so possibly you
            if [ "${IPV6LL}" = "${OwnIpv6}" ]; then
                IPV4Address=$(ip -4 addr show ${interface} | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p')
                Info="You"
                HostName=$(host ${IPV4Address} $(route get default | grep gateway | cut -d":" -f2) | grep name | head -n1 | cut -d" " -f5 | cut -d"." -f1)
            else
                IPV4Address=""
                Info=""
                HostName=""
            fi
        else #IPv4 found so now decididng if router or not
            if (echo "$RouterLocalNeighbours" | grep -q ${IPV6LL}) ; then Info="Router"; else Info="Node" ; fi
            HostName=$(host ${IPV4Address} $(route get default | grep gateway | cut -d":" -f2) | grep name | head -n1 | cut -d" " -f5 | cut -d"." -f1)
        fi
        if [ -z "${IPV4Address}" ]; then IPV4Address="NotFound" ; Info="IPv6only?" ; fi
        if [[ ${LongMAC} == *"incomplete"* ]]; then LongMAC="00:00:00:00:00:00" ; fi
        printf "%26s %1s %39s %1s %17s %1s %15s %1s %9s (%s)\n" ${IPV6LL} "|" ${IPV6G} "|" ${LongMAC} "|" ${IPV4Address} "|" ${Info} ${HostName}
    done
    echo "---------------------------|-----------------------------------------|-------------------|-----------------|-------------------------------"
}

f_usage(){ #echo usage
	echo "[+] ipv6finder.sh v${version}"
	echo "[+] Usage: ipv6finder.sh [{interface}]"
	echo "[+] Example: ipv6finder.sh eth0"
  exit 1
}

hash arp-scan 2>/dev/null || { echo >&2 "[+] I require arp-scan but it's not installed.  Aborting."; exit 1; }

if [[ $1 = "" ]] ; then
	f_usage
else
	interface=$1
fi

f_main
exit 0
