#!/bin/bash

[ -f /tmp/netconn.run ] && exit
[ ! -f /tmp/netconn.pid ] && echo 0 >/tmp/netconn.pid
[ "$(cat /tmp/netconn.pid)" != 0 ] && exit

touch /tmp/netconn.run
NAME=sysmonitor
APP_PATH=/usr/share/$NAME
SYSLOG='/var/log/sysmonitor.log'

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

sys_exit() {
	#echolog "netconn is off."
	[ -f /tmp/netconn.run ] && rm -rf /tmp/netconn.run
	syspid=$(cat /tmp/netconn.pid)
	syspid=$((syspid-1))
	echo $syspid > /tmp/netconn.pid
	exit 0
}

#echolog "netconn is on."
syspid=$(cat /tmp/netconn.pid)
syspid=$((syspid+1))
echo $syspid > /tmp/netconn.pid
while [ "1" == "1" ]; do
	netconn=$(netcat -lnp 55556)
	func=${netconn:0:1}
	netconn=${netconn:2}
	case $func in
		1)
#			$APP_PATH/sysapp.sh cron_regvpn &
			$APP_PATH/sysapp.sh $netconn &
			;;
		2)
#			$APP_PATH/sysapp.sh next_vpn &
			$APP_PATH/sysapp.sh $netconn &
			;;
		*)
			echo $netconn > /tmp/test.netconn
			;;
	esac
 	[ ! -f /tmp/netconn.run ] && sys_exit
 	[ "$(cat /tmp/netconn.pid)" -gt 1 ] && sys_exit
done
