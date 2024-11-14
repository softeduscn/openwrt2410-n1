#!/bin/bash

[ -f /tmp/sysmonitor.run ] && exit
[ "$(cat /tmp/sysmonitor.pid)" != 0 ] && exit

NAME=sysmonitor
APP_PATH=/usr/share/$NAME
SYSLOG='/var/log/sysmonitor.log'
touch /tmp/sysmonitor.run

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$SYSLOG
	number=$(cat $SYSLOG|wc -l)
	[ $number -gt 25 ] && sed -i '1,10d' $SYSLOG
}

uci_get_by_name() {
	local ret=$(uci get $1.$2.$3 2>/dev/null)
	echo ${ret:=$4}
}

uci_set_by_name() {
	uci set $1.$2.$3=$4 2>/dev/null
	uci commit $1
}

ping_url() {
	local url=$1
	for i in $( seq 1 3 ); do
		status=$(ping -c 1 -W 1 $url | grep -o 'time=[0-9]*.*' | awk -F '=' '{print$2}'|cut -d ' ' -f 1)
		[ "$status" == "" ] && status=0
		[ "$status" != 0 ] && break
	done
	echo $status
}

sys_exit() {
	echolog "Sysmonitor is off."
	[ -f /tmp/sysmonitor.run ] && rm -rf /tmp/sysmonitor.run
	syspid=$(cat /tmp/sysmonitor.pid)
	syspid=$((syspid-1))
	echo $syspid > /tmp/sysmonitor.pid
	exit 0
}

mask() {
    num=$((4294967296 - 2 ** (32 - $1)))
    for i in $(seq 3 -1 0); do
        echo -n $((num / 256 ** i))
        num=$((num % 256 ** i))
        if [ "$i" -eq "0" ]; then
            echo
        else
            echo -n .
        fi
    done
}

check_ip() {
	if [ ! -n "$1" ]; then
		#echo "NO IP!"
		echo ""
	else
 		IP=$1
    		VALID_CHECK=$(echo $IP|awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print "yes"}')
		if echo $IP|grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$">/dev/null; then
			if [ ${VALID_CHECK:-no} == "yes" ]; then
				# echo "IP $IP available."
				echo $IP
			else
				#echo "IP $IP not available!"
				echo ""
			fi
		else
			#echo "IP is name convert ip!"
			dnsip=$(nslookup $IP|grep Address|sed -n '2,2p'|cut -d' ' -f2)
			if [ ! -n "$dnsip" ]; then
				#echo "Inull"
				echo $test
			else
				#echo "again check"
				echo $(check_ip $dnsip)
			fi
		fi
	fi
}

passwall_log() {
	show_num=30
	if [ -f /tmp/log/passwall.log ]; then
		num=$(cat /tmp/log/passwall.log|wc -l)
		if [ "$num" -gt $show_num ]; then
			let num=num-$show_num
			sed -i "1,${num}d" /tmp/log/passwall.log
		fi
	fi
}

sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null
echolog "Sysmonitor is on."
syspid=$(cat /tmp/sysmonitor.pid)
syspid=$((syspid+1))
echo $syspid > /tmp/sysmonitor.pid
while [ "1" == "1" ]; do
	passwall_log
	VPNtype=$(uci_get_by_name $NAME $NAME vpn 'NULL')
	if [ $VPNtype == 'WireGuard' ]; then
		status=$(ping_url '1.1.1.1 -I wan')
		for i in $status
		do
			if [ $i == 0 ]; then
				echolog "ifup wan"
				ifup wan
				break
			fi
		done
	fi
	proto=$(uci get network.lan.proto)
	case $proto in
		dhcp)
			lanip=$(ip -o -4 addr list br-lan|cut -d ' ' -f7)
			if [ -n "$lanip" ]; then
				mask=$(mask $(echo $lanip|cut -d'/' -f2))
				lanip=$(echo $lanip|cut -d'/' -f1)
				lan=$(uci_get_by_name $NAME $NAME ipaddr)
				if [ "$lan" != $lanip ]; then
					gateway=$(check_ip $(ip route|grep default|cut -d' ' -f3))
					if [ -n "$gateway" ]; then
						uci set sysmonitor.sysmonitor.ipaddr=$lanip
						uci set sysmonitor.sysmonitor.netmask=$mask
						uci set sysmonitor.sysmonitor.gateway=$gateway
						uci commit sysmonitor
					fi
				fi
			fi
			;;
	esac
	num=0
	check_time=$(uci_get_by_name $NAME $NAME systime 10)
	[ "$check_time" -le 3 ] && check_time=3
	chktime=$((check_time-1))
	while [ $num -le $check_time ]; do
		touch /tmp/test.$NAME
		prog='netconn chkvpn'
		for i in $prog
		do
			progsh=$i'.sh'
			progpid='/tmp/'$i'.pid'
			[ "$(pgrep -f $progsh|wc -l)" == 0 ] && echo 0 > $progpid
			[ ! -f $progpid ] && echo 0 > $progpid
			arg=$(cat $progpid)
			case $arg in
				0)
					[ "$(pgrep -f $progsh|wc -l)" != 0 ] && killall $progsh
					progrun='/tmp/'$i'.run'
					[ -f $progrun ] && rm $progrun
					[ -f $progpid ] && rm $progpid
					$APP_PATH/$progsh &
					;;
				1)
					if [ "$i" == "netconn" ]; then
						case $num in
							2)
							[ -f /tmp/test.$i ] && rm /tmp/test.$i
							ip=$(ip -o -4 addr list br-wan| cut -d ' ' -f7)
							wanip=$(echo $ip|cut -d'/' -f1)
							echo '9-test-'$si |netcat -nc $wanip 55555
							;;
						$chktime)
							[ ! -f /tmp/test.$i ] && killall $progsh
							;;
						esac
					fi
					if [ "$i" == "chkvpn" ] && [ "$num" == $chktime ]; then
						if [ ! -f /tmp/test.$i ]; then	
							killall $progsh
						else
							rm /tmp/test.$i
						fi
					fi
					;;
				*)
					killall $progsh
					echo 0 > $progpid
					;;
			esac
		done
		[ ! -f /tmp/sysmonitor.run ] && sys_exit
		[ "$(uci_get_by_name $NAME $NAME enable 0)" == 0 ] && sys_exit
		[ "$(cat /tmp/sysmonitor.pid)" != 1 ] && sys_exit
		sleep 1
		num=$((num+1))
		if [ -f "/tmp/sysmonitor" ]; then
			rm /tmp/sysmonitor
			break
		fi
	done
done
