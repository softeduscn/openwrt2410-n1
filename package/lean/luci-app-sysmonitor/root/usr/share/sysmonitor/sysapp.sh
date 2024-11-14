#!/bin/bash

NAME=sysmonitor
APP_PATH=/usr/share/$NAME
SYSLOG='/var/log/sysmonitor.log'
device='s905d_n1'
[ ! -f /tmp/sysmonitor.pid ] && echo 0 >/tmp/sysmonitor.pid

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$SYSLOG
	number=$(cat $SYSLOG|wc -l)
	[ $number -gt 25 ] && sed -i '1,10d' $SYSLOG
}

echoddns() {
	[ $(uci_get_by_name $NAME $NAME ddnslog 0) == 0 ] && return
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$SYSLOG
	number=$(cat $SYSLOG|wc -l)
	[ $number -gt 25 ] && sed -i '1,10d' $SYSLOG
}

uci_get_by_name() {
	local ret=$(uci get $1.$2.$3 2>/dev/null)
	echo ${ret:=$4}
}

uci_get_by_type() {
	local ret=$(uci get $1.@$2[0].$3 2>/dev/null)
	echo ${ret:=$4}
}

uci_set_by_name() {
	uci set $1.$2.$3=$4 2>/dev/null
	uci commit $1
}

uci_set_by_type() {
	uci set $1.@$2[0].$3=$4 2>/dev/null
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

set_static() {
	status=$(ping_url 192.168.1.1)
	if [ "$status" != 0 ]; then
		proto static
	else
		echo "30=touch /tmp/set_static.sign" >> /tmp/delay.sign
	fi
}

firstrun(){
	sed -i '/sysapp.sh/d' /etc/crontabs/root
	#每天2点更新vpn地址集
	echo "0 2 * * * /usr/share/sysmonitor/sysapp.sh update_vpn_data" >> /etc/crontabs/root
	#每周六2点启动dns数据更新
	echo "0 2 * * 6 /usr/share/sysmonitor/sysapp.sh update_dns_data" >> /etc/crontabs/root
	$APP_PATH/sysapp.sh update_dns_data
	if [ "$(cat /etc/shadow|grep root:::|wc -l)" != 0 ]; then
		utc_secs=$(date +%s)
		days=$(( utc_secs / 86400 ))
		pass='$1$zi2Q3mx.$FKnJLxOCjUxEX22lf3sXx0'
		sed -i "s/root.*$/root:$pass:${days}:0:99999:7:::/g" /etc/shadow
	fi
	[ -f /usr/share/passwall/test.sh ] && cp /usr/share/passwall/test.sh $APP_PATH
	cat /etc/config/passwall|grep "config nodes"|cut -d"'" -f2 > /tmp/goodnode
	file='/tmp/nodeinfo'
	nodes=$(cat /etc/config/passwall|grep "config nodes"|cut -d"'" -f2)
	echo '' > $file
	for i in $nodes
	do
		protocol=$(uci_get_by_name passwall $i protocol '')
		if [ "$protocol" == '_shunt' ]; then
			proxy=$(uci_get_by_name passwall $i Proxy '')
			vpnname=$(uci get passwall.$i.type)'='$(uci get passwall.$i.remarks)
			vpnname=$vpnname' proxy='$(uci get passwall.$proxy.type)'-'$(uci get passwall.$proxy.remarks)
#			echo '204:0.000000 *'$i' '$vpnname>> $file
		else
			vpnname=$(uci get passwall.$i.type)'='$(uci get passwall.$i.remarks)
#			echo '204:0.000001 '$i' '$vpnname>> $file
		fi
		echo '204:0.000000 '$i' '$vpnname>> $file
	done
	sed -i '/^$/d' $file
	sysdir='/etc/sysmonitor'
	mv $sysdir/fs.lua /usr/lib/lua/luci
	destdir=''
	mvdir $sysdir $destdir
	setdns
	echo 0 > /tmp/vpn_status
	getip
	uci del network.utun
	uci commit network
	/etc/init.d/network restart &
	touch /tmp/makehost.sign
	sed -i 's_downloads.openwrt.org_mirrors.cloud.tencent.com/openwrt_' /etc/opkg/distfeeds.conf
	[ "$(pgrep -f sysmonitor.sh|wc -l)" == 0 ] && $APP_PATH/monitor.sh
	crontab /etc/crontabs/root
	echo "15=touch /tmp/firstrun" >> /tmp/delay.sign
}

mvdir() {
cd $1
home=$(pwd)
mydir=$(ls)
for i in $mydir
do
if [ -d $i ]; then
	myhome=$(pwd)
	cd $i
	mvdir=$(ls)
	mvdir $myhome/$i $2/$i
	cd $myhome
else
	mv $i $2
fi
done
chmod 0755 /etc/ipset-rules/*.sh  
}

ipsec_users() {
	if [ -f "/usr/sbin/ipsec" ]; then
		users=$(/usr/sbin/ipsec status|grep xauth|grep ESTABLISHED|wc -l)
		usersl2tp=$(top -bn1|grep options.xl2tpd|grep -v grep|wc -l)
		let "users=users+usersl2tp"
		[ "$users" == 0 ] && users='None'
	else
		users='None'
	fi
	echo $users
}

pptp_users() {
	if [ -f "/usr/sbin/pppd" ]; then
		users=$(top -bn1|grep options.pptpd|grep -v grep|wc -l)
#		let users=users-1
		[ "$users" == 0 ] && users='None'
	else
		users='None'
	fi
	echo $users
}

getip() {
#	ip=$(ip -o -4 addr list br-lan | cut -d ' ' -f7 | cut -d'/' -f1)
#	echo $ip >/www/ip.html
	cat /www/ip.html
}

getip6() {
#	ip=$(ip -o -6 addr list br-lan | cut -d ' ' -f7| cut -d'/' -f1 | head -n1)
#	echo $ip >/www/ip6.html
	cat /www/ip6.html
}

wg_users() {
file='/var/log/wg_users'
/usr/bin/wg >$file
m=$(sed -n '/peer/=' $file | sort -r -n )
k=$(cat $file|wc -l)
let "k=k+1"
s=$k
for n in $m
do 
	let "k=s-n"
	if [ $k -le 3 ] ;then 
		let "s=s-1"
		tmp='sed -i '$n,$s'd '$file
		$tmp
	else
		let "i=n+3"
		tmp='sed -n '$i'p '$file
		tmp=$($tmp|cut -d' ' -f6)
		[ "$tmp" == "day," ] && tmp="days,"
		[ "$tmp" == "hour," ] && tmp="hours,"
		[ "$tmp" == "minute," ] && tmp="minutes,"
		case $tmp in
		days,)
			let "s=s-1"
			tmp='sed -i '$n,$s'd '$file
			$tmp
			;;
		hours,)
			let "s=s-1"
			tmp='sed -i '$n,$s'd '$file
			$tmp
			;;
		minutes,)
			tmp='sed -n '$i'p '$file
			tmp=$($tmp|cut -d' ' -f5)
			if [ $tmp -ge 3 ] ;then
				let "s=s-1"
				tmp='sed -i '$n,$s'd '$file
				$tmp
			fi
			;;
		esac
	fi
	s=$n
done
#users=$(cat $file|sed "/GWLcAE1Of.*$/d"|sed "/bmXOC.*$/d"|grep peer|wc -l)
users=$(cat $file|grep peer|wc -l)
#[ "$users" -eq 0 ] && users='None'
echo $users
}

wg() {
	if [ "$(uci_get_by_name $NAME $NAME wgenable 0)" == 0 ]; then
		if [ "$(ifconfig |grep wg[0-9] |cut -c3-3|wc -l)" != 0 ]; then
			wg_name=$(ifconfig |grep wg[0-9] |cut -c1-3)
			for x in $wg_name; do
			    ifdown $x &
			done
		fi
	else
		if [ "$(ifconfig |grep wg[0-9] |cut -c3-3|wc -l)" != 3 ]; then
			wg=$(ifconfig |grep wg[0-9] |cut -c1-3)
			wg_name="wg1 wg2 wg3"
			for x in $wg_name; do
				[ "$(echo $wg|grep $x|wc -l)" == 0 ] && ifup $x
			done
		fi
	fi
	wg=$(ifconfig |grep wg[0-9] |cut -c1-3)
	echo $wg
}

switch_ipsecfw() {
	if [ "$(uci get firewall.@zone[0].masq)" == 1 ]; then
		uci set firewall.@zone[0].mtu_fix=0
		uci set firewall.@zone[0].masq=0
	else
		uci set firewall.@zone[0].mtu_fix=1
		uci set firewall.@zone[0].masq=1
	fi
	uci commit firewall
	/etc/init.d/firewall restart >/dev/null 2>&1
}

getgateway() {
	uci get network.lan.gateway
}

getdns() {
	uci get network.lan.dns
}

test_url() {
	local url=$1
	local try=1
	[ -n "$2" ] && try=$2
	local timeout=2
	[ -n "$3" ] && timeout=$3
	local extra_params=$4
	curl --help all | grep "\-\-retry-all-errors" > /dev/null
	[ $? == 0 ] && extra_params="--retry-all-errors ${extra_params}"
	status=$(/usr/bin/curl -I -o /dev/null -skL $extra_params --connect-timeout ${timeout} --retry ${try} -w %{http_code} "$url")
	case "$status" in
		404|204|\
		200)
			status=200
		;;
		*)
			status=0
		;;
	esac
	echo $status
}

curl_url() {
	for i in $( seq 1 2 ); do
		result=$(curl -s --connect-timeout 1 $1|grep google|wc -l)
		[ -n "$result" ] && break
	done
	echo $result
}

getvpn() {
	hostname=$(uci get system.@system[0].hostname)
	vpn=$(uci_get_by_name $NAME $NAME vpn NULL)
	if [ "$vpn" != 'NULL' ]; then
		status=$(ping_url www.google.com)
		if [ "$status" != 0 ]; then
			urlchk=$(uci_get_by_name $NAME $NAME urlchk 0)
			[ "$urlchk" == 1 ] && status=$(test_url "https://www.google.com/generate_204")
			[ "$status" != 0 ] && status=1
			testchk=$(uci_get_by_name $NAME $NAME testvpn 0)
			if [ "$chkvpn" == 1 ]; then
				if [ "$status" != 0 ]; then
					case $vpn in
						Passwall)
							node=$(uci get passwall.@global[0].tcp_node)
							status=$($APP_PATH/test.sh url_test_node $node)
							if [ "${status:0:1}" != 0 ]; then
								status='1'
							else
								status=0
							fi
							;;
					esac
				fi
			fi
		fi
	fi
	if [ ! -f /tmp/passwall_start ]; then
	if [ "$status" == 0 ]; then
		num=$(cat /tmp/delay.list|grep nextvpn|wc -l)
		if [ "$num" == 0 ]; then
			nextvpntime=$(uci_get_by_name $NAME $NAME nextvpntime 3)
			nextvpntime=$((nextvpntime*60))
			echo "$nextvpntime=$APP_PATH/sysapp.sh nextvpn" >> /tmp/delay.sign
		fi
	fi
	fi

	status=$status'-'$vpn
	case $vpn in
		Passwall)
			node=$(uci get passwall.@global[0].tcp_node)
			remark=$(uci get passwall.$node.remarks)
			type=$(uci get passwall.$node.type)
			protocol=$(uci get passwall.$node.protocol)
			if [ "$protocol" == '_shunt' ]; then
				proxy=$(uci get passwall.$node.Proxy)
				remark1=$(uci get passwall.$proxy.remarks)
				type1=$(uci get passwall.$proxy.type)
				remark=$remark' '$type1'-'$remark1
			fi
			passwall_start=''
			[ -f /tmp/passwall_start ] && passwall_start='*'
			status=$status' '$passwall_start$type' '$remark
		;;
		Shadowsocksr)
			node=$(uci get shadowsocksr.@global[0].global_server)
			type=$(uci get shadowsocksr.$node.type)
			remark=$(uci get shadowsocksr.$node.alias)
			status=$status' '$type' '$remark
		;;
		*)
			type=$(uci_get_by_name $NAME $NAME vpn 'NULL')
			status=$status$type
		;;
	esac
echo $status > /tmp/vpns
echo $status
regvpn
}

getvpns() {
	[ ! -f /tmp/vpns ] && echo "0-not connect..." > /tmp/vpns
	cat /tmp/vpns
}

smartdns_cache() {
	[ -f /tmp/smartdns.cache ] && rm /tmp/smartdns.cache
	reload "smartdns"
}

setdns_port() {
	local_port=$(uci_get_by_name $NAME $NAME local_port '6053')
	oversea_port=$(uci_get_by_name $NAME $NAME oversea_port '8653')
	oversea=$oversea_port' '$(uci_get_by_name $NAME $NAME oversea '')
	mosdns_port=$(uci_get_by_name $NAME $NAME mosdns_port '53')
	smartdns_conf='/etc/smartdns/custom.conf'
	sed -i "/bind/d" $smartdns_conf
	sed -i "/local&oversea/abind-tcp [::]:$oversea" $smartdns_conf
	sed -i "/local&oversea/abind [::]:$oversea" $smartdns_conf
	sed -i "/local&oversea/abind-tcp [::]:$local_port" $smartdns_conf
	sed -i "/local&oversea/abind [::]:$local_port" $smartdns_conf

	mosdns_conf='/etc/mosdns/config_custom.yaml'
	m=$(sed -n '/smartdns_local_port/=' $mosdns_conf)
	m=$((m+1))
	sed -i $m's/127.0.0.1:.*/127.0.0.1:'$local_port'"/' $mosdns_conf
	m=$(sed -n '/smartdns_oversea_port/=' $mosdns_conf)
	m=$((m+1))
	sed -i $m's/127.0.0.1:.*/127.0.0.1:'$oversea_port'"/' $mosdns_conf
	sed -i 's/listen:.*/listen: ":'$mosdns_port'"/' $mosdns_conf
	setdns
}

setdns() {
	dns=$(uci_get_by_name $NAME $NAME dns 'NULL')
	if [ "$dns" == 'NULL' ]; then
		close_dns
	else
		dns_port=$(uci_get_by_name $NAME $NAME mosdns_port '53')
		set_port=0
		[ "$dns_port" != '53' ] && set_port=''
		uci set dhcp.@dnsmasq[0].port=$set_port
		uci commit dhcp
		/etc/init.d/odhcpd reload
		/etc/init.d/dnsmasq reload
		uci set smartdns.@smartdns[0].enabled='1'
		uci set smartdns.@smartdns[0].auto_set_dnsmasq='0'
		uci set smartdns.@smartdns[0].port=$(uci_get_by_name $NAME $NAME local_port '6053')
		uci set smartdns.@smartdns[0].seconddns_port=$(uci_get_by_name $NAME $NAME oversea_port '8653')
		uci commit smartdns
		reload "smartdns"
		uci set mosdns.config.redirect=1
		uci set mosdns.config.enabled=1
		uci commit mosdns
		reload "mosdns"
	fi
}

selvpn() {
	setdns
	vpn=$(uci_get_by_name $NAME $NAME vpn 'NULL')
	case $vpn in
	WireGuard)
		if [ "$(uci_get_by_name $NAME $NAME dns 'NULL')" == 'NULL' ]; then
			uci set sysmonitor.sysmonitor.dns="SmartDNS"
			uci commit sysmonitor
		fi
		if [ "$(ipset list ipv6_CN|wc -l)" == 0 ]; then
			/etc/ipset-rules/ipv4_CN.sh &
			/etc/ipset-rules/ipv6_CN.sh &
		fi
		#[ "$(ps |grep -v grep|grep passwall|sed '/passwall2/d'|wc -l)" != 0 ] && /etc/init.d/passwall stop
		#[ "$(ps |grep -v grep|grep passwall2|wc -l)" != 0 ] && /etc/init.d/passwall2 stop
		#[ "$(ps |grep /etc/ssrplus|grep -v grep|wc -l)" != 0 ] && /etc/init.d/shadowsocksr stop
		#[ "$(ps |grep -v grep|grep /usr/share/openclash|wc -l)" != 0 ] && /etc/init.d/openclash stop
		#[ "$(ps |grep -v grep|grep mwan3|wc -l)" == 0 ] && /etc/init.d/mwan3 start
		[ -n "$(pgrep -f passwall)" ] && /etc/init.d/passwall stop
		[ -n "$(pgrep -f passwall2)" ] && /etc/init.d/passwall2 stop
		[ -n "$(pgrep -f ssrplus)" ] && /etc/init.d/shadowsocksr stop
		[ -n "$(pgrep -f openclash)" ] && /etc/init.d/openclash stop
		[ -n "$(pgrep -f mwan3)" ] && /etc/init.d/mwan3 start
		;;
	Passwall)
		#[ "$(ps |grep -v grep|grep mwan3|wc -l)" != 0 ] && /etc/init.d/mwan3 stop	
		#[ "$(ps |grep /etc/ssrplus|grep -v grep|wc -l)" != 0 ] && /etc/init.d/shadowsocksr stop
		#[ "$(ps |grep -v grep|grep /usr/share/openclash|wc -l)" != 0 ] && /etc/init.d/openclash stop
		#[ "$(ps |grep -v grep|grep passwall2|wc -l)" != 0 ] && /etc/init.d/passwall2 stop
		[ -n "$(pgrep -f mwan3)" ] && /etc/init.d/mwan3 stop	
		[ -n "$(pgrep -f ssrplus)" ] && /etc/init.d/shadowsocksr stop
		[ -n "$(pgrep -f openclash)" ] && /etc/init.d/openclash stop
		[ -n "$(pgrep -f passwall2)" ] && /etc/init.d/passwall2 stop
		reload "passwall"
		;;
	Passwall2)
		#[ "$(ps |grep -v grep|grep mwan3|wc -l)" != 0 ] && /etc/init.d/mwan3 stop
		#[ "$(ps |grep /etc/ssrplus|grep -v grep|wc -l)" != 0 ] && /etc/init.d/shadowsocksr stop
		#[ "$(ps |grep -v grep|grep /usr/share/openclash|wc -l)" != 0 ] && /etc/init.d/openclash stop
		#[ "$(ps |grep -v grep|grep passwall|sed '/passwall2/d'|wc -l)" != 0 ] && /etc/init.d/passwall stop
		[ -n "$(pgrep -f mwan3)" ] && /etc/init.d/mwan3 stop
		[ -n "$(pgrep -f ssrplus)" ] && /etc/init.d/shadowsocksr stop
		[ -n "$(pgrep -f openclash)" ] && /etc/init.d/openclash stop
		[ -n "$(pgrep -f passwall)" ] && /etc/init.d/passwall stop
		reload "passwall2"
		;;
	Shadowsocksr)
		#[ "$(ps |grep -v grep|grep mwan3|wc -l)" != 0 ] && /etc/init.d/mwan3 stop
		#[ "$(ps |grep -v grep|grep passwall|sed '/passwall2/d'|wc -l)" != 0 ] && /etc/init.d/passwall stop
		#[ "$(ps |grep -v grep|grep passwall2|wc -l)" != 0 ] && /etc/init.d/passwall2 stop
		#[ "$(ps |grep -v grep|grep /usr/share/openclash|wc -l)" != 0 ] && /etc/init.d/openclash stop
		[ -n "$(pgrep -f mwan3)" ] && /etc/init.d/mwan3 stop
		[ -n "$(pgrep -f passwall)" ] && /etc/init.d/passwall stop
		[ -n "$(pgrep -f passwall2)" ] && /etc/init.d/passwall2 stop
		[ -n "$(pgrep -f openclash)" ] && /etc/init.d/openclash stop
		reload "shadowsocksr"
		;;
	Openclash)
		#[ "$(ps |grep -v grep|grep mwan3|wc -l)" != 0 ] && /etc/init.d/mwan3 stop
		#[ "$(ps |grep -v grep|grep passwall|sed '/passwall2/d'|wc -l)" != 0 ] && /etc/init.d/passwall stop
		#[ "$(ps |grep -v grep|grep passwall2|wc -l)" != 0 ] && /etc/init.d/passwall2 stop
		#[ "$(ps |grep /etc/ssrplus|grep -v grep|wc -l)" != 0 ] && /etc/init.d/shadowsocksr stop
		[ -n "$(pgrep -f mwan3)" ] && /etc/init.d/mwan3 stop
		[ -n "$(pgrep -f passwall)" ] && /etc/init.d/passwall stop
		[ -n "$(pgrep -f passwall2)" ] && /etc/init.d/passwall2 stop
		[ -n "$(pgrep -f ssrplus)" ] && /etc/init.d/shadowsocksr stop
		uci set openclash.config.enable=1
		uci commit openclash
		reload "openclash"
		;;
	*)
		#[ "$(ps |grep -v grep|grep mwan3|wc -l)" != 0 ] && /etc/init.d/mwan3 stop
		#[ "$(ps |grep -v grep|grep passwall|sed '/passwall2/d'|wc -l)" != 0 ] && /etc/init.d/passwall stop
		#[ "$(ps |grep -v grep|grep passwall2|wc -l)" != 0 ] && /etc/init.d/passwall2 stop
		#[ "$(ps |grep /etc/ssrplus|grep -v grep|wc -l)" != 0 ] && /etc/init.d/shadowsocksr stop
		#[ "$(ps |grep -v grep|grep /usr/share/openclash|wc -l)" != 0 ] && /etc/init.d/openclash stop
		[ -n "$(pgrep -f mwan3)" ] && /etc/init.d/mwan3 stop
		[ -n "$(pgrep -f passwall)" ] && /etc/init.d/passwall stop
		[ -n "$(pgrep -f passwall2)" ] && /etc/init.d/passwall2 stop
		[ -n "$(pgrep -f ssrplus)" ] && /etc/init.d/shadowsocksr stop
		[ -n "$(pgrep -f openclash)" ] && /etc/init.d/openclash stop
		;;
	esac
	touch /tmp/sysmonitor
}

shadowsocksr() {
	#if [ "$(uci get shadowsocksr.@global[0].pdnsd_enable)" == 0 ]; then
	#	uci set sysmonitor.sysmonitor.dns="SmartDNS"
	#	#uci set sysmonitor.sysmonitor.port='53'
	#fi
	uci set sysmonitor.sysmonitor.vpn="Shadowsocksr"
	uci commit sysmonitor
	selvpn
}

passwall() {
	uci set passwall.@global[0].enabled=1
	uci commit passwall
	uci set sysmonitor.sysmonitor.vpn="Passwall"
	uci set sysmonitor.sysmonitor.dns="SmartDNS"
	uci commit sysmonitor
	selvpn
}

passwall2() {
	uci set passwall2.@global[0].enabled=1
	uci commit passwall2
	uci set sysmonitor.sysmonitor.vpn="Passwall2"
	uci commit sysmonitor
	selvpn
}

openclash() {
	uci set sysmonitor.sysmonitor.vpn="Openclash"
	uci commit sysmonitor
	selvpn
}

dl_smartdnsfile() {
	num=$(sed -n '/download-file/'p /etc/config/smartdns|wc -l)
	for((i=0;i<num;i++));  
	do   
 		url=$(uci get smartdns.@download-file[$i].url)
		name=$(uci get smartdns.@download-file[$i].name)
		wget -O /etc/smartdns/domain-set/$name $url -q
	done 
}

reload() {
	action=1
	para="reload"
	case $1 in
	passwall2)
		#[ "$(ps |grep -v grep|grep passwall2|wc -l)" == 0 ] && para="start"
		[ ! -n "$(pgrep -f passwall2)" ] && para="start"
		;;
	passwall)
		#[ "$(ps |grep -v grep|grep passwall|sed '/passwall2/d'|wc -l)" != 0 ] && para="start"
		[ ! -n "$(pgrep -f passwall)" ] && para="start"
		;;
	shadowsocksr)
		#[ "$(ps -w |grep /etc/ssrplus|grep -v grep |wc -l)" == 0 ] && para="start"
		[ ! -n "$(pgrep -f ssrplus)" ] && para="start"
		;;
	openclash)
		#[ "$(ps |grep /usr/share/openclash|grep -v grep |wc -l)" == 0 ] && para="start"
		[ ! -n "$(pgrep openclash)" ] && para="start"
		;;
	smartdns)
		#[ "$(ps |grep -v grep|grep smartdns|wc -l)" == 0 ] && para="start"
		[ ! -n "$(pgrep -f smartdns)" ] && para="start"
		;;
	mosdns)
		#[ "$(ps |grep -v grep|grep mosdns|wc -l)" == 0 ] && para="start"
		[ ! -n "$(pgrep -f mosdns)" ] && para="start"
		;;
	*)
		action=0
		;;
	esac
	if [ $action == 1 ]; then
		/etc/init.d/$1 $para &
	fi
}

close_dns() {
	[ -n "$(pgrep -f smartdns)" ] && /etc/init.d/smartdns stop 2>/dev/null
	[ -n "$(pgrep -f mosdns)" ] && /etc/init.d/mosdns stop 2>/dev/null
	uci set dhcp.@dnsmasq[0].port=''
	uci commit dhcp
	/etc/init.d/dnsmasq reload
}

close_vpn() {
	uci set sysmonitor.sysmonitor.vpn='NULL'
	uci set sysmonitor.sysmonitor.dns='NULL'
	uci commit sysmonitor
	selvpn
}

setdelay_offon() {
	enabled=0
	[ -n "$2" ] && enabled=1		
	prog_num=$(cat /etc/config/sysmonitor|grep prog_list|wc -l)
	num=0
	while (($num<$prog_num))
	do
		program=$(uci_get_by_name $NAME @prog_list[$num] program)
		if [ "$program" == $1 ]; then
			uci_set_by_name $NAME @prog_list[$num] enabled $enabled
			uci commit $NAME
			break
		fi
		num=$((num+1))
	done
}

getdata() {
	data_num=$(cat /etc/config/sysmonitor|grep data_list|wc -l)
	num=0
	status=-1
	while (($num<$data_num))
	do
		datalist=$(uci_get_by_name $NAME @data_list[$num] datalist)
		if [ "$datalist" == $1 ]; then
			status=$(uci_get_by_name $NAME @data_list[$num] $2)
			break
		fi
		num=$((num+1))
	done
echo $status
}

getdelay() {
	prog_num=$(cat /etc/config/sysmonitor|grep prog_list|wc -l)
	num=0
	status=-1
	while (($num<$prog_num))
	do
		program=$(uci_get_by_name $NAME @prog_list[$num] program)
		if [ "$program" == $1 ]; then
			status=$(uci_get_by_name $NAME @prog_list[$num] $2)
			break
		fi
		num=$((num+1))
	done
echo $status
}

get_delay() {
	prog_num=$(cat /etc/config/sysmonitor|grep prog_list|wc -l)
	num=0
	status=-1
	while (($num<$prog_num))
	do
		program=$(uci_get_by_name $NAME @prog_list[$num] program)
		path=$(uci_get_by_name $NAME @prog_list[$num] path "/usr/share/sysmonitor/sysapp.sh")
		cycle=$(uci_get_by_name $NAME @prog_list[$num] cycle 5)
		enabled=$(uci_get_by_name $NAME @prog_list[$num] enabled 0)
		if [ "$program" == $1 ]; then
			status=$enabled$cycle'='$path' '$program
			break
		fi
		num=$((num+1))
	done
echo $status
}

delay_prog() {
	status=$(get_delay $1)
	if [ "$status" != "" ]; then
		enabled=${status:0:1}
		status=${status:1}
		program=$(echo $status|cut -d' ' -f2)
		if [ -n "$2" ]; then
			status=$2'='$(echo $status|cut -d'=' -f2-)
			setdelay_offon $program 1
			echo $status >> /tmp/delay.sign
		else
			[ "$enabled" == 1 ] && echo $status >> /tmp/delay.sign
		fi	
	fi
}

chk_prog() {
prog_num=$(cat /etc/config/sysmonitor|grep prog_list|wc -l)
num=0
while (($num<$prog_num))
do
	program=$(uci_get_by_name $NAME @prog_list[$num] program)
	path=$(uci_get_by_name $NAME @prog_list[$num] path "/usr/share/sysmonitor/sysapp.sh")
	enabled=$(uci_get_by_name $NAME @prog_list[$num] enabled 0)
	status=$(cat /tmp/delay.list|grep $program|wc -l)
	if [ "$status" == 0 ]; then
		cycle=$(uci_get_by_name $NAME @prog_list[$num] cycle 200)
		enabled=$(uci_get_by_name $NAME @prog_list[$num] enabled 0)
		[ "$enabled" == 1 ] && echo $cycle'='$path' '$program >> /tmp/delay.sign
	else	
		[ "$enabled" == 0 ] && sed -i "/$program/d" /tmp/delay.list
	fi
	num=$((num+1))
done
}

get_first_node() {
nodes=$(cat /tmp/goodnode)
for i in $nodes 
do
protocol=$(uci_get_by_name passwall $i protocol 'NULL')
if [ "$protocol" != '_shunt' ]; then
	break
fi
done
echo $i
}

next_vpn() {
[ -f /tmp/next_vpn.run ] && exit
vpn=$(uci_get_by_name $NAME $NAME vpn 'NULL')
[ $vpn == "NULL" ] && exit
if [ ! -f /tmp/forceNextVPN ]; then
	for i in {1..2}; do
		vpn1=$(getvpn)
		if [ "${vpn1:0:1}" == 1 ]; then
			echo ${vpn1:0}
			exit
		fi
	done
	node=$(uci get passwall.@global[0].tcp_node)
	protocol=$(uci get passwall.$node.protocol)
	if [ "$protocol" != '_shunt' ]; then
		sed -i "/$node/d" /tmp/goodnode
		sed -i "/$node/d" /tmp/nodeinfo
	fi
	touch /tmp/firstnode
else
	rm /tmp/forceNextVPN
fi
touch /tmp/next_vpn.run
case $vpn in
	Passwall)
		[ ! -f /tmp/goodnode ] &&  cat /etc/config/passwall|grep "config nodes"|cut -d"'" -f2 > /tmp/goodnode
		if [ "$(cat /tmp/goodnode|wc -l)" -ne 0 ]; then
			nodes=$(cat /tmp/goodnode)
			firstnode=$(get_first_node)
			nodes=$nodes' '$firstnode
			current=$(uci get passwall.@global[0].tcp_node)
			protocol=$(uci_get_by_name passwall $current protocol '')
			[ "$protocol" == '_shunt' ] && current=$(uci_get_by_name passwall $current Proxy)
			arg=0
#			cat /tmp/goodnode | grep $current > /dev/null
#			[ $? -ne 0 ] && arg=1
			[ -f /tmp/firstnode ] && arg=1 && rm /tmp/firstnode
			case $arg in
			1)
				next_node=$firstnode
				i=$firstnode
				;;
			0)
				status=$(echo $nodes|grep $current|wc -l)
				[ "$status" == 0 ] && current=$firstnode
				next_node=''
				for i in $nodes 
				do
					if [ "$next_node" != '' ]; then
						next_node=$i
						break
					fi
					[ $i == $current ] && next_node=$i
				done	
				;;
			esac
			mynode=$(uci_get_by_name passwall @global[0] tcp_node)
			protocol=$(uci_get_by_name passwall $mynode protocol '')
#			[ "$(uci_get_by_name $NAME $NAME shunt NULL)" == 0 ] && protocol=''
			if [ "$protocol" == '_shunt' ]; then
				uci_set_by_name passwall $mynode Proxy $next_node
			else
				uci_set_by_name passwall @global[0] tcp_node $next_node
			fi
			uci commit passwall
			echo "" > /tmp/log/passwall.log
			vpn=$(uci_get_by_name $NAME $NAME vpn NULL)
			status='0-*'$vpn
			node=$(uci get passwall.@global[0].tcp_node)
			remark=$(uci get passwall.$node.remarks)
			type=$(uci get passwall.$node.type)
			protocol=$(uci_get_by_name passwall $node protocol '')
			if [ "$protocol" == '_shunt' ]; then
				node1=$(uci get passwall.$node.Proxy)
				remark1=$(uci get passwall.$node1.remarks)
				type1=$(uci get passwall.$node1.type)
				remark=$remark' proxy='$type1'-'$remark1
				sed -i "s/204:0.000000.*/204:0.000000 $node $type=$remark/g" /tmp/nodeinfo
			fi
			status=$status' '$type' '$remark	
			echo $status > /tmp/vpns
			/etc/init.d/passwall stop
			/etc/init.d/passwall start &
#			vpnname=$(uci get passwall.$i.type)' '$(uci get passwall.$i.remarks)
#			echolog $vpnname" node to be used."
#		else
#			echolog "Passwall no node to use!"
		fi
		;;
	Shadowsocksr)
		current=$(uci get shadowsocksr.@global[0].global_server)
		nodes=$(cat /etc/config/shadowsocksr|grep "config servers"|wc -l)
		firstnode=$(uci show shadowsocksr.@servers[0].type|cut -d'.' -f2)
		let nodes=nodes-1
		if [ "$nodes" -ne 0 ]; then
			next_node=''
			for i in $( seq 0 $nodes ); do
				node=$(uci show shadowsocksr.@servers[$i].type|cut -d'.' -f2)
				if [ -n "$next_node" ]; then
					next_node=$node
					uci set shadowsocksr.@global[0].global_server=$node
					uci commit shadowsocksr
					/etc/init.d/shadowsocksr stop
					/etc/init.d/shadowsocksr start &
					break
				fi	
				[ $node == $current ] && next_node=$node
			done
			if [ "$nodes" == $i ]; then
				node=$firstnode
				uci set shadowsocksr.@global[0].global_server=$node
				uci commit shadowsocksr
				/etc/init.d/shadowsocksr stop
				/etc/init.d/shadowsocksr start &
			fi
#			vpnname=$(uci get shadowsocksr.$node.alias)
#			echolog "Shadowsocksr next node..."$vpnnake
#		else
#			echolog "Shadowsocksr no node to use!"
		fi
		;;
esac
echo 0 > /tmp/vpn_status
rm -rf /tmp/next_vpn.run
touch /tmp/sysmonitor
}

nextvpn() {
	hostname=$(uci get system.@system[0].hostname)
	if [ "$(uci_get_by_name $NAME $NAME nextvpn 0)" == 1 ]; then
		touch /tmp/nextvpn.sign
#	else
#		touch /tmp/getvpn.sign
	fi
	vpn=$(uci_get_by_name $NAME $NAME vpn 'NULL')
	ipaddr=$(ip -o -4 addr list br-lan | cut -d ' ' -f7 | cut -d'/' -f1)
	status="("$ipaddr")"$hostname'-'$vpn
	case $vpn in
		Passwall)
			node=$(uci get passwall.@global[0].tcp_node)
			remark=$(uci get passwall.$node.remarks)
			type=$(uci get passwall.$node.type)
			status=$status' '$type' '$remark
		;;
		Shadowsocksr)
			node=$(uci get shadowsocksr.@global[0].global_server)
			type=$(uci get shadowsocksr.$node.type)
			remark=$(uci get shadowsocksr.$node.alias)
			status=$status' '$type' '$remark
		;;
	esac
	echo $status
}

checknode() {
	[ -f /tmp/checknode ] && exit
	touch /tmp/checknode
	vpn=$(uci_get_by_name $NAME $NAME vpn 'NULL')
	case $vpn in
		Passwall)
			nodes=$(cat /etc/config/passwall|grep "config nodes"|cut -d"'" -f2)
			echo '' >/tmp/testnode
			for i in $nodes
			do
				protocol=$(uci_get_by_name passwall $i protocol '')
				if [ "$protocol" == '_shunt' ]; then
					proxy=$(uci_get_by_name passwall $i Proxy '')
					vpnname=$(uci get passwall.$i.type)'='$(uci get passwall.$i.remarks)
					vpnname=$vpnname' proxy='$(uci get passwall.$proxy.type)'-'$(uci get passwall.$proxy.remarks)
					echo '204:0.000000 '$i' '$vpnname>> /tmp/testnode
				else
				status=$($APP_PATH/test.sh url_test_node $i)
				if [ "${status:0:1}" -ne 0 ]; then
					vpnname=$(uci get passwall.$i.type)'-'$(uci get passwall.$i.remarks)
					echo $status' '$i' '$vpnname>> /tmp/testnode
				fi
				fi
			done
			sort /tmp/testnode|cut -d' ' -f2|sed '/^$/d' > /tmp/goodnode
			sort /tmp/testnode|sed '/^$/d' > /tmp/nodeinfo
			;;
	esac
	rm /tmp/checknode
}

proto() {
	if [ -n "$1" ]; then
		proto=$1
	else
		proto="dhcp"
		[ "$(uci get network.lan.proto)" == 'dhcp' ] && proto="static"		
	fi
	proto_lan=$(uci get network.lan.proto)
	[ "$proto" == $proto_lan ] && exit
	case $proto in
		dhcp)
			uci set network.lan.proto='dhcp'
			uci del network.lan.dns
			uci del network.lan.netmask
			uci del network.lan.ipaddr
			uci del network.lan.gateway
			;;
		static)
			uci set network.lan.proto='static'
			uci del network.lan.dns
			uci set network.lan.ipaddr=$(uci get sysmonitor.sysmonitor.ipaddr)
			uci set network.lan.netmask=$(uci get sysmonitor.sysmonitor.netmask)
			uci set network.lan.gateway=$(uci get sysmonitor.sysmonitor.gateway)
			dnslist=$(uci_get_by_name $NAME $NAME dnslist '192.168.1.1')
			for i in $dnslist
			do
				uci add_list network.lan.dns=$i
			done
			;;
	esac
	uci set network.lan.ip6assign=''
	uci set network.lan.force_link='0'
	uci commit network
	ifup lan
	/etc/init.d/odhcpd restart
}

regvpn() {
	reg_name=$(uci get system.@system[0].hostname)
	reg_ip=$(ip -o -4 addr list br-lan | cut -d ' ' -f7 | cut -d'/' -f1)
	reg_port='55555'
	reg_vpn=$(getvpns)
	host_num=$(cat /etc/config/sysmonitor|grep host_list|wc -l)
	num=0
	while (($num<$host_num))
	do
		hostip=$(uci get sysmonitor.@host_list[$num].hostip)
		echo '1'$reg_ip'-'$reg_name'-'$reg_vpn|netcat -nc $hostip $reg_port &
		num=$((num+1))
	done
}

makehost() {
	num=$(cat /etc/config/dhcp|grep "config domain"|wc -l)
	if [ "$num" != 0 ]; then
		while (($num>0))
		do
			num=$((num-1))
			uci del dhcp.@domain[$num]
		done
	fi
	host_num=$(cat /etc/config/sysmonitor|grep host_list|wc -l)
	num=0
	while (($num<$host_num))
	do
		hostname=$(uci get sysmonitor.@host_list[$num].hostname)
		hostip=$(uci get sysmonitor.@host_list[$num].hostip)
		dhcp=$(uci add dhcp domain)
		uci set dhcp.$dhcp.name=$hostname
		uci set dhcp.$dhcp.ip=$hostip
		num=$((num+1))
	done
	uci commit dhcp
	/etc/init.d/odhcpd restart
	/etc/init.d/dnsmasq reload
}

update_ddns() {
	[ $(uci_get_by_name $NAME $NAME ddns 0) == 0 ] && exit
	vpn=$(cat /tmp/vpns)
	[ "${vpn:0:1}" != 1 ] && exit 
	[ -f /tmp/update_ddns ] && exit
	touch /tmp/update_ddns
	echoddns 'Update DDNS'
	echoddns '-------------------'
	ddns_num=$(cat /etc/config/sysmonitor|grep ddns_list|wc -l)
	num=0
	ipv4=$(curl -s http://members.3322.org/dyndns/getip)
	while (($num<$ddns_num))
	do
		iptype=$(uci get sysmonitor.@ddns_list[$num].iptype)
		hostname=$(uci get sysmonitor.@ddns_list[$num].hostname)
		url=$(uci get sysmonitor.@ddns_list[$num].url)
		username=$(uci get sysmonitor.@ddns_list[$num].username)
		password=$(uci get sysmonitor.@ddns_list[$num].password)
		if [ "$iptype" == 'ip6' ]; then
			getip=$(uci get sysmonitor.@ddns_list[$num].getip)
			ddns_ip='ipv6='$($getip)
		else
			ddns_ip='ipv4='$ipv4
		fi
		ddns_url='curl  -s  --connect-timeout 1 '$url'?hostname='$hostname'&my'$ddns_ip'&username='$username'&password='$password
		ddns_status=$($ddns_url)
		echoddns $hostname'='$ddns_status
		num=$((num+1))
	done
	echoddns '-------------------'
	rm /tmp/update_ddns
}

getddnsip() {
	ddns_num=$(cat /etc/config/sysmonitor|grep ddns_list|wc -l)
	num=0
	while (($num<$ddns_num))
	do
		iptype=$(uci get sysmonitor.@ddns_list[$num].iptype)
		hostname=$(uci get sysmonitor.@ddns_list[$num].hostname)
		if [ "$iptype" == 'ip6' ]; then
			ipaddr=$(host $hostname|grep IPv6|cut -d' ' -f5)
		else
			ipaddr=$(host $hostname|grep 'has address'|cut -d' ' -f4)
		fi
		uci set sysmonitor.@ddns_list[$num].ipaddr=$ipaddr
		num=$((num+1))
	done
	uci commit sysmonitor
}

stopdl() {
	sed -i '/Download Firmware/,$d' $SYSLOG
	[ -f /tmp/$NAME.log.tmp ] && cp /tmp/$NAME.log.tmp $SYSLOG
	[ -f /tmp/$NAME.log.tmp ] && rm /tmp/$NAME.log.tmp
	[ -f /tmp/sysupgrade ] && rm /tmp/sysupgrade
	dl=$(pgrep -f $device)
	[ -n "$dl" ] && kill $dl
	firmware=$(uci_get_by_name $NAME $NAME firmware)
	tmp=$(echo $firmware|cut -d'/' -f 9)
 	[ -f /tmp/upload/$tmp ] && rm /tmp/upload/$tmp
}

firmware() {
#	num=$(cat $SYSLOG|wc -l)
#	num=$((num-2))
#	[ "$num" -gt 0 ] && sed -i "1,${num}d" $SYSLOG
	[ ! -d "/tmp/upload" ] && mkdir /tmp/upload
	cd /tmp/upload
	stopdl
	[ ! -f /tmp/$NAME.log.tmp ] && cp $SYSLOG /tmp/$NAME.log.tmp
	firmware=$(uci_get_by_name $NAME $NAME firmware)
	[ "$1" != '' ] && firmware=$1
	echo "" > $SYSLOG
	echolog "Download Firmware:"$tmp"..."
	echolog "If download slowly,please use vpn!!!"
	echo '------------------------------------------------------------------------------------------------------' >> $SYSLOG
	echolog ""
	wget  --no-check-certificate -c $firmware -O $tmp >> $SYSLOG 2>&1
	if [ $? == 0 ]; then
		sed -i '/Download Firmware/a\ ' $SYSLOG
		sed -i '/Download Firmware/a\********************************************* ' $SYSLOG
		sed -i '/Download Firmware/a\****** Download Firmware is OK.Please Upgrade '$tmp $SYSLOG
		sed -i '/Download Firmware/a\ ' $SYSLOG
	else
		[ -f /tmp/upload/$tmp ] && rm /tmp/upload/$tmp
		sed -i '/Download Firmware/,$d' $SYSLOG
		echolog "Download Firmware is error! please use vpn & try again."
		echo '------------------------------------------------------------------------------------------------------' >> $SYSLOG
	fi
}

sysupgrade() {
	num=$(cat $SYSLOG|wc -l)
	num=$((num-2))
	[ "$num" -gt 0 ] && sed -i "1,${num}d" $SYSLOG
	file=$(ls /tmp/upload|grep $device)
	if [ -n "$file" ]; then
		echo '------------------------------------------------------------------------------------------------------' > $SYSLOG
		sysupgrade='/usr/sbin/openwrt-update-amlogic /tmp/upload/'$file' no no-restore'
		echo $sysupgrade >> $SYSLOG
		touch /tmp/sysupgrade
		$sysupgrade >> $SYSLOG 2>/dev/null
	else
		sed -i '/Download Firmware/,$d' $SYSLOG
		echolog "Download Firmware"
		echolog "No sysupgrade file? Please upload $device sysupgrade file or download."
		echo '------------------------------------------------------------------------------------------------------' >> $SYSLOG
	fi
}

sysbutton() {
	case $1 in
	prog)
	#	button='<input type="button" class="button1" value="Show/Hiden" id="app" onclick="fun()" />'
		prog_num=$(cat /etc/config/sysmonitor|grep prog_list|wc -l)
		num=0
		while (($num<$prog_num))
		do
			program=$(uci get sysmonitor.@prog_list[$num].program)
			name=$(uci get sysmonitor.@prog_list[$num].name)
			button=$button' <button class=button1><a href="sysmenu?sys='$program'&sys1=&redir=prog">'$name'</a></button>'
			num=$((num+1))
		done
		;;
	prog_list)
		button='<B>'
		while read i
		do
			color='MediumAquamarine'
			timeid=$(echo $i|cut -d'=' -f1)
			[ "$timeid" -le 20 ] && color='MediumSeaGreen '
			[ "$timeid" -le 10 ] && color='Green '
			[ "$(echo $i|cut -d' ' -f2)" != 'chkprog' ] && button=$button' <font color='$color'>'$i'</font><BR>'
		done < /tmp/delay.list
		button=$button'</B>'
		;;
	data_list)
		data_num=$(cat /etc/config/sysmonitor|grep data_list|wc -l)
		data_list=$(uci_get_by_name $NAME $NAME datalist)
		num=0
		status=-1
		button=''
		while (($num<$data_num))
		do
			name=$(uci_get_by_name $NAME @data_list[$num] name)
			datalist=$(uci_get_by_name $NAME @data_list[$num] datalist)
			color='button1'
			[ "$data_list" == $datalist ] && color='button3'
			button=$button' <button class="'$color'"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=datalist&sys1='$datalist'&redir=data">'$name'</a></button>'
			num=$((num+1))
		done
		;;
	node_list)
		vpn=$(uci get passwall.@global[0].tcp_node)
		nodenums=$(cat /tmp/nodeinfo|wc -l)
		nodenum=$(sed -n /$vpn/= /tmp/nodeinfo)
		name=$(getdelay checknode name)
		button=$button'<button class="button1" title="Update VPN nodes"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=checknode&sys1=&redir=prog">'$name'('$nodenum'-'$nodenums')</a></button>'
		vpns=$(cat /tmp/vpns)
		type=$(echo ${vpns:1}|cut -d'-' -f2|cut -d' ' -f1|tr A-Z a-z)
		button=$button' <button class="button1" title="Goto VPN setting"><a href="/cgi-bin/luci/admin/services/'$type'" target="_blank">'$type'-></a></button><BR><BR>'
		redir='node'
		num=101
		while read i
		do
			node=$(echo $i|cut -d' ' -f2)
			link=''
			protocol=$(uci_get_by_name passwall $node protocol '')
			if [ "$protocol" == '_shunt' ]; then
				shunt=$(uci get sysmonitor.sysmonitor.shunt)
				if [ "$shunt" == 1 ]; then
					myshunt='禁用分流总节点'
					mybox=' <input type="checkbox" checked="checked" />'
				else
					myshunt='启用分流总节点'
					mybox=' <input type="checkbox" />'
				fi
				link=$link' '$mybox' <button class="button1" title="Set shunt mode"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=shunt&sys1=&redir=node">'$myshunt'</a></button>'	
			fi
			if [ "$vpn" == $node ]; then
				color='green'
				status=$(cat /tmp/vpns)
				if [ "${status:0:1}" == 0 ]; then
					color='red'
					link=$link' <button class="button1" title="Update VPN connection"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=UpdateVPN&sys1=&redir=node">UpdateVPN</a></button>'
				fi
			else
				color='grey'
			fi
			tmp="$num"
			tmp='-'${tmp:1}
			button=$button'<button class="button1" title="Select this node for VPN service"><a href="sysmenu?sys=vpn_node&sys1='$node'&redir='$redir'">Sel'$tmp'</a></button> <B><font color='$color'>'$i'</font></B>'$link'<BR>'
			num=$((num+1))
		done < /tmp/nodeinfo
		;;
	lantitle)
		proto=$(uci get network.lan.proto)
		if [ "$proto" == 'dhcp' ]; then
			proto="set->static"
		else
			proto="set->dhcp"
		fi
		button=' <button class="button1" title="Network LAN '$proto'"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=proto&sys1=&redir=system">'$proto'</a></button>'
		;;
	lan)
		proto=$(uci get network.lan.proto)
		button='<font color=6699cc>LAN('$proto') '$(getip)'</font> <font color=9699cc>['$(getip6)']</font>'
		[ "$proto" == 'static' ] && button=$button'<BR><font color=6699cc>gateway:'$(uci get network.lan.gateway)'</font> <font color=9699cc>dns:'$(uci get network.lan.dns)'</font>'
		;;
	vpntitle)
		vpn=$(uci_get_by_name $NAME $NAME vpn 'NULL')
		case $vpn in
		Passwall)
		[ ! -f /tmp/goodnode ] && cat /etc/config/passwall|grep "config nodes"|cut -d"'" -f2 > /tmp/goodnode
		current=$(uci get passwall.@global[0].tcp_node)
		nodenums=$(cat /tmp/goodnode|wc -l)
		nodenum=$(sed -n /$current/= /tmp/goodnode)
		[ "$nodenum" == '' ] && nodenum=0
		button=' <button class="button1"  title="Select next node"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=nextVPN&sys1=&redir=system">nextVPN('$nodenum'-'$nodenums')</a></button>'
		if [ "$nodenum" != 1 ]; then
			button=' <button class="button1" title="Select first node"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=firstVPN&sys1=&redir=system">firstVPN</a></button>'$button
		fi
		;;
		NULL)
		button=''
		;;
		*)
		button=' <button class="button1" title="Select next node"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=nextVPN&sys1=&redir=system">nextVPN</a></button>'
		;;
		esac
		;;
	vpn)
		vpns=$(getvpns)
#		hostname=$(uci get system.@system[0].hostname)
		vpntype=$(uci_get_by_name $NAME $NAME vpn 'NULL')
		if [ ${vpns:0:1} == 0 ]; then
			color='red'
		else
			color='green'
		fi
		if [ "$vpntype" != 'NULL' ]; then
			type=$(echo ${vpns:1}|cut -d'-' -f2|cut -d' ' -f1|tr A-Z a-z)
			name=$(echo $vpns|cut -d' ' -f2-)
			button='<a href="/cgi-bin/luci/admin/services/'$type'" target="_blank"><font color='$color'>'$name'</font></a>'
	#		button=$button' <button class="button1" title="Close VPN"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=CloseVPN&sys1=&redir=system">CloseVPN</a></button>'
			button=$button' <button class="button1" title="Update VPN connection"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=UpdateVPN&sys1=&redir='$redir'">UpdateVPN</a></button>'
			#button=$button' <button class="button1" title="Goto VPN setting"><a href="/cgi-bin/luci/admin/services/'$type'" target="_blank">'$type'-></a></button>'
		else
			button=''
		fi
		;;
	buttontitle)
		button=''
		redir='system'
		[ "$(uci get sysmonitor.sysmonitor.ddnslog)" == 1 ] && redir='log'
		#button=' <button class="button1"><a href="/cgi-bin/luci/admin/services/ttyd" target="_blank">Terminal</a></button>'
		#button=$button' <button class="button1" title="Update VPN nodes"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=checknode&sys1=&redir='$redir'">UpdateNODE</a></button>'
		dns=$(uci_get_by_name $NAME $NAME dns 'NULL')
		if [ "$dns" != "NULL" ]; then
			#button=$button' <button class=button4 title="Close DNS"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=closedns&sys1=&redir=system">关闭dns</a></button>'
			button=$button' <button class=button4 title="Restart DNS"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=restartdns&sys1=&redir=system">Restart-dns</a></button>'
		fi
		;;
	button)
		group0=''
		group1=''
		group2=''
		group3=''
		vpn=$(uci_get_by_name $NAME $NAME vpn 'NULL')
		dns=$(uci_get_by_name $NAME $NAME dns 'NULL')
		if [ -f /etc/init.d/smartdns ]; then
			dnsname='SmartDNS'
#			status=$(get_delay smartdns_update)
#			[ "${status:0:1}" == 1 ] && dnsname=$dnsname'***'
			#if [ "$dns" == 'SmartDNS' ]; then
				if [ ! -n "$(pgrep -f smartdns)" ]; then
					button=' <button class=button2 title="SmartDNS is not ready...,restart"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=service_smartdns&sys1=&redir=system">'$dnsname'</a></button>'
					group2=$group2$button
				else
					button=' <button class=button1 title="Goto smartdns setting"><a href="/cgi-bin/luci/admin/services/smartdns" target="blank">'$dnsname'</a></button>'
					group1=$group1$button
				fi
			#else
				#button=' <button class=button3 title="Start smartdns"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=service_smartdns&sys1=&redir=system">'$dnsname'</a></button>'
				#group3=$group3$button
			#fi
		fi
		if [ -f /etc/init.d/mosdns ]; then
			dnsname='MosDNS'
			status=$(get_delay mosdns_update)
			[ "${status:0:1}" == 1 ] && dnsname=$dnsname'***'
			#if [ "$dns" == 'MosDNS' ]; then
				if [ ! -n "$(pgrep -f mosdns)" ]; then
					button=' <button class=button2 title="MosDNS is not ready...,restart"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=service_mosdns&sys1=&redir=system">'$dnsname'</a></button>'
					group2=$group2$button
				else
					button=' <button class=button1 title="Goto MosDNS setting"><a href="/cgi-bin/luci/admin/services/mosdns" target="blank">'$dnsname'</a></button>'
					group1=$group1$button
				fi
			#else
				#button=' <button class=button3 title="Start MosDNS"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=service_mosdns&sys1=&redir=system">'$dnsname'</a></button>'
				#group3=$group3$button
			#fi
		fi
		if [ -f /etc/init.d/shadowsocksr ]; then
			if [ "$vpn" != 'Shadowsocksr' ]; then
				group3=$group3' <button class="button3" title="Start Shadowsocksr"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=Shadowsocksr&sys1=&redir=system">Shadowsocksr</a></button>'
			fi
		fi
		if [ -f /etc/init.d/passwall ]; then
			if [ "$vpn" != 'Passwall' ]; then
				group3=$group3' <button class="button3" title="Start Passwall"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=Passwall&sys1=&redir=system">Passwall</a></button>'
			fi
		fi
		if [ -f /etc/init.d/passwall2 ]; then
			if [ "$vpn" != 'Passwall2' ]; then
				group3=$group3' <button class="button3" title="Start passwall2"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=Passwall2&sys1=&redir=system">Passwall2</a></button>'
			fi
		fi
		if [ -f /etc/init.d/openclash ]; then
			if [ "$vpn" != 'Openclash' ]; then
				group3=$group3' <button class="button3" title="Start openclash"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=Openclash&sys1=&redir=system">Openclash</a></button>'
			fi
		fi
		button=$group0$group1$group3$group2
		;;
	wg_title)
		button=''
		;;
	wg_state)
		wguser=$(wg_users)
		if [ "$wguser" == 0 ]; then
			button=''
		else
			button='<a href="/cgi-bin/luci/admin/sys/sysmonitor/wgusers">Wireguard online users:</a> <font color=green>'$wguser'</font>'
		fi
		;;
	esac
echo $button
}
	
sysmenu() {
	case $1 in
	datalist)
		uci set sysmonitor.sysmonitor.datalist=$2
		uci commit sysmonitor
		;;
	stopdl)
		stopdl
		;;
	firmware)
		firmware
		;;
	sysupgrade)
		sysupgrade
		;;
	VPNswitch)
		nextvpn=$(uci_get_by_name $NAME $NAME nextvpn)
		if [ "$nextvpn" == 1 ]; then
			uci_set_by_name $NAME $NAME nextvpn 0
		else
			uci_set_by_name $NAME $NAME nextvpn 1
		fi
		uci commit sysmonitor
		;;
	shunt)
		shunt=$(uci_get_by_name $NAME $NAME shunt)
		if [ "$shunt" == 1 ]; then
			uci_set_by_name $NAME $NAME shunt 0
		else
			uci_set_by_name $NAME $NAME shunt 1
		fi
		uci commit sysmonitor
		;;
	URLchkVPN)
		urlchk=$(uci_get_by_name $NAME $NAME urlchk)
		if [ "$urlchk" == 1 ]; then
			uci_set_by_name $NAME $NAME urlchk 0
		else
			uci_set_by_name $NAME $NAME urlchk 1
		fi
		uci commit sysmonitor
		;;
	TESTchkVPN)
		testchk=$(uci_get_by_name $NAME $NAME testchk)
		if [ "$testchk" == 1 ]; then
			uci_set_by_name $NAME $NAME testchk 0
		else
			uci_set_by_name $NAME $NAME testchk 1
		fi
		uci commit sysmonitor
		;;
	vpn_node)
		mynode=$(uci_get_by_name passwall @global[0] tcp_node)
		[ "$mynode" == $2 ] && exit
		vpn=$(uci_get_by_name $NAME $NAME vpn NULL)
		status='0-'$vpn
		node=$2
		protocol=$(uci_get_by_name passwall $mynode protocol '')		
		[ "$(uci_get_by_name $NAME $NAME shunt NULL)" == 0 ] && protocol=''
		if [ "$protocol" == '_shunt' ]; then
			uci_set_by_name passwall $mynode Proxy $2
			remark=$(uci get passwall.$mynode.remarks)
			type=$(uci get passwall.$mynode.type)
			remark1=$(uci get passwall.$node.remarks)
			type1=$(uci get passwall.$node.type)
			remark=$remark' proxy='$type1'-'$remark1
			sed -i "s/204:0.000000.*/204:0.000000 $mynode $type=$remark/g" /tmp/nodeinfo
		else
			protocol=$(uci_get_by_name passwall $node protocol '')
			if [ "$protocol" == "_shunt" ]; then
				uci_set_by_name $NAME $NAME shunt 1
				uci commit sysmonitor
			fi
			uci_set_by_name passwall @global[0] tcp_node $node
			remark=$(uci get passwall.$node.remarks)
			type=$(uci get passwall.$node.type)		
		fi
		status=$status' *'$type' '$remark	
		uci commit passwall
		echo $status > /tmp/vpns
		/etc/init.d/passwall stop
		/etc/init.d/passwall start &
		;;
	ShowProg)
		file='/usr/lib/lua/luci/view/sysmonitor/prog.htm'
		status=$(cat $file|grep block|wc -l)
		if [ "$status" == 1 ]; then
			sed -i s/block/none/g $file
		else
			sed -i s/none/block/g $file
		fi
		;;
	closedns)
		uci set sysmonitor.sysmonitor.dns='NULL'
		uci commit sysmonitor
		close_dns
		;;
	restartdns)
		setdns
		#dns=$(uci_get_by_name $NAME $NAME dns 'NULL'|tr A-Z a-z)
		#reload $dns
		;;
	service_smartdns)
		uci set sysmonitor.sysmonitor.dns='SmartDNS'
		uci commit sysmonitor
		setdns
		;;
	service_mosdns)
		uci set sysmonitor.sysmonitor.dns='MosDNS'
		uci commit sysmonitor
		setdns
		;;
	firstVPN)
		#[ "$(ps |grep -v grep|grep next_vpn|wc -l)" == 0 ] && [ -f /tmp/next_vpn.run ] && rm /tmp/next_vpn.run
		[ ! -n "$(pgrep -f next_vpn)" ] && [ -f /tmp/next_vpn.run ] && rm /tmp/next_vpn.run
		touch /tmp/firstnode
		touch /tmp/forceNextVPN
		touch /tmp/nextvpn.sign
		;;
	nextVPN)
		#[ "$(ps |grep -v grep|grep next_vpn|wc -l)" == 0 ] && [ -f /tmp/next_vpn.run ] && rm /tmp/next_vpn.run
		[ ! -n "$(pgrep -f next_vpn)" ] && [ -f /tmp/next_vpn.run ] && rm /tmp/next_vpn.run
		touch /tmp/forceNextVPN
		touch /tmp/nextvpn.sign
		;;
	CloseVPN)
		close_vpn
		;;
	UpdateVPN)
		getvpn
		regvpn
		;;
	Updatenode)
		checknode &
		;;
	Shadowsocksr)
		shadowsocksr
		;;
	Passwall)
		passwall
		;;
	Passwall2)
		passwall2
		;;
	Openclash)
		openclash
		;;
	proto)
		proto
		;;
	*)
		prog=$(uci_get_by_name $NAME $NAME prog)
		delay_prog $1 $prog
		;;
	esac
}

chkapp() {
	[ "$(pgrep -f chkvpn.sh|wc -l)" -gt 1 ] && killall chkvpn.sh
	[ "$(pgrep -f netconn.sh|wc -l)" -gt 1 ] && killall netconn.sh
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
		fi
	fi
}

get_ip() {
	if [ ! -n "$1" ]; then
		#echo "NO IP!"
		echo ""
	else
 		IP=$1
		#echo "IP is name convert ip!"
		dnsip=$(ping -4 -c 1 -W 1 $IP|grep from|cut -d' ' -f4|cut -d':' -f1)
#		if [ ! -n "$dnsip" ]; then
			#echo "Inull"
			echo $dnsip
#		else
#			#echo "again check"
#			echo $(get_ip $dnsip)
#		fi
	fi
}


mosdns_update() {
	mosdns_dir='/etc/sysmonitor/rule'
	tmpdir=$(mktemp -d) || exit 1
	url=$(uci_get_by_name $NAME $NAME mosdns_url)
	wget -O $tmpdir/apple-cn.txt $url/apple-cn.txt
	if [ $? == 0 ]; then
		cp $tmpdir/apple-cn.txt $mosdns_dir
		wget -O $tmpdir/google-cn.txt $url/google-cn.txt
		if [ $? == 0 ]; then
			cp $tmpdir/google-cn.txt $mosdns_dir
			setdelay_offon mosdns_update
			[ -n "$(pgrep -f mosdns)" ] && /etc/init.d/mosdns restart
		fi
	fi
	rm -rf $tmpdir	
	#/usr/share/mosdns/mosdns.sh geodata > /dev/null 2>&1			
}

smartdns_update() {
	tmpdir=$(mktemp -d) || exit 1
	/usr/share/sysmonitor/gfwlist2dnsmasq.sh -l -o $tmpdir/gfwlist > /dev/null 2>&1
	if [ $? == 0 ]; then
		cp $tmpdir/gfwlist /etc/smartdns/domain-set
		setdelay_offon smartdns_update
		dns=$(uci_get_by_name $NAME $NAME dns 'NULL')
		[ "$dns" == 'SmartDNS' ] && reload smartdns
	fi
	rm -rf $tmpdir
}

pwdata_update() {
	status=$(cat /tmp/vpns)
	if [ "${status:0:1}" == 1 ]; then
		uci set passwall.@global_rules[0].geoip_update=1
		uci set passwall.@global_rules[0].geosite_update=1
		uci commit passwall
		/usr/share/passwall/rule_update.lua
		[ $? == 0 ] && setdelay_offon pwdata_update
		[ $? == 0 ] && [ -n "$(pgrep -f mosdns)" ] && /etc/init.d/mosdns restart
	fi
}

vpnsets() {
	mosdns_dir='/etc/sysmonitor/rule'
	vpnsite=$mosdns_dir'/vpnsite.txt'
	vpnip=$mosdns_dir'/vpnip.txt'
	cat /etc/config/passwall|grep address|cut -d' ' -f3|sed "s/\'//g" > $vpnsite
	[ -f $vpnip ] && rm $vpnip
	addrlist=$(cat $vpnsite)	
	for i in $addrlist
	do
		ip=$(check_ip $i)
		if [ -n "$ip" ]; then
			echo $ip >> $vpnip
			sed -i "/"$ip"/d" $vpnsite
		fi
	done
	status=$(ping_url 192.168.1.1)
	if [ "$status" != 0 ]; then
		vpnsets='/etc/sysmonitor/rule/vpnsets'
		nodes=$(cat /etc/config/passwall|grep "config nodes"|cut -d' ' -f3|sed "s/\'//g")
		num=0
		[ -f $vpnsets ] && rm $vpnsets
		for i in $nodes 
		do
			num=$((num+1))
			protocol=$(uci_get_by_name passwall $i protocol '')
			if [ "$protocol" == '_shunt' ]; then
				proxy=$(uci_get_by_name passwall $i Proxy '')
				addr=$(uci get passwall.$proxy.address)
				i='*'$i
			else
				addr=$(uci get passwall.$i.address)
			fi
			ip=$(check_ip $addr)
			[ ! -n "$ip" ] && ip=$(get_ip $addr)
			len=$(echo $addr|awk '{print length}')
			[ "$len" -lt 15 ] && addr=$addr'\t'
			echo -e $num'\t'$i' '$addr'\t'$ip >> $vpnsets
		done
		setdelay_offon vpnsets
	fi
	delay_prog vpnsets
}

arg1=$1
shift
case $arg1 in
logup)
	status=$(cat $SYSLOG|grep "Download Firmware"|wc -l)
#	if [ "$status" == 0 ]; then
#		status=$(cat $SYSLOG|grep "Upgrade Firmware"|wc -l)
#	fi
	file="/usr/lib/lua/luci/view/sysmonitor/log.htm"
	sed -i "/cbi-button/d" $file
	if [ ! -f /tmp/sysupgrade ]; then
	redir='log'
	if [ "$status" != 0 ]; then
		sed -i "/user_fieldset/a\\\t<input class='cbi-button cbi-input-apply' type='button' onclick=location.href='sysmenu?sys=sysupgrade&sys1=&redir="$redir"' value='<%:Upgrade%>' />" $file
		sed -i "/user_fieldset/a\\\t<input class='cbi-button cbi-input-apply' type='button' onclick=location.href='sysmenu?sys=stopdl&sys1=&redir="$redir"' value='<%:Stop%>' />" $file
		sed -i "/user_fieldset/a\\\t<input class='cbi-button cbi-input-apply' type='button' onclick=location.href='sysmenu?sys=firmware&sys1=&redir="$redir"' value='<%:Download%>' />" $file
#		sed -i "/user_fieldset/a\\\t<input class='cbi-button cbi-input-apply' type='button' onclick=location.href='sysmenu?sys=update&sys1=&redir="$redir"' value='<%:Upload%>' />" $file
	else
		sed -i "/user_fieldset/a\\\t<input class='cbi-button cbi-input-apply' type='button' onclick=location.href='sysmenu?sys=firmware&sys1=&redir="$redir"' value='<%:Download Firmware%>' />" $file
		sed -i "/user_fieldset/a\\\t<input class='cbi-button cbi-input-apply' type='button' onclick='clearlog()' name='clean log' value='<%:Clear logs%>' />" $file
	fi
	fi
	;;
makehost)
	makehost
	;;
cron_regvpn)
	regvpn
	delay_prog cron_regvpn
	;;
cron_chkvpn)
	getvpn
	delay_prog cron_chkvpn
	;;
checknode)
	checknode
	delay_prog checknode
	;;
proto)
	proto $1
	;;
regvpn)
	regvpn
	;;
sysmenu)
	sysmenu $1 $2
	;;
sysbutton)
	sysbutton $1
	;;
reload_dns)
	dns=$(uci get sysmonitor.sysmonitor.dns|tr A-Z a-z)
	[ ! $dns == "null" ] && reload $dns
	;;
reload_vpn)
	vpn=$(uci get sysmonitor.sysmonitor.vpn|tr A-Z a-z)
	[ ! $vpn == "null" ] && reload $vpn
	;;
close_vpn)
	close_vpn
	;;
openclash)
	openclash
	;;
passwall)
	passwall
	;;
passwall2)
	passwall2
	;;
shadowsocksr)
	shadowsocksr
	;;
setdns_port)
	setdns_port
	;;
setdns)
	setdns
	;;
selvpn)
	selvpn
	;;
getip)
	getip
	;;
getip6)
	getip6
	;;
getgateway)
	getgateway
	;;
getvpns)
	getvpns
	;;
getvpn)
	getvpn
	;;
ipsec)
	ipsec_users
	;;
pptp)
	pptp_users
	;;
wg)
	wg_users
	;;
dl_smartdnsfile)
	dl_smartdnsfile
	;;
next_vpn)
	next_vpn
	;;
nextvpn)
	nextvpn
	;;
firstrun)
	firstrun
	;;
switch_ipsecfw)
	switch_ipsecfw
	;;
getdns)
	getdns
	;;
smartdns_cache)
	smartdns_cache
	;;
getddnsip)
	getddnsip
	;;
set_static)
	set_static
	;;
getdata)
	getdata $1 $2
	;;
getdelay)
	getdelay $1 $2
	;;
vpnsets)
	vpnsets
	;;
pwdata_update)
	pwdata_update
	;;
smartdns_update)
	smartdns_update
	delay_prog smartdns_update
	;;
mosdns_update)
	mosdns_update
	delay_prog mosdns_update
	;;
update_dns_data)
	setdelay_offon mosdns_update 1
#	setdelay_offon smartdns_update 1
	setdelay_offon pwdata_update 1
	;;
update_vpn_data)
	setdelay_offon vpnsets 1
	;;
chkprog)
	chk_prog
	chkprog=$(uci_get_by_name $NAME $NAME chkprog 60)
	echo $chkprog'='$APP_PATH'/sysapps.sh chkprog' >> /tmp/delay.sign
	;;
passwall_start)
	touch /tmp/passwall_start
	uci_set_by_name $NAME $NAME dns 'MosDNS'
	uci commit passwall
	setdns
	;;
passwall_end)
	[ -f /tmp/passwall_start ] && rm /tmp/passwall_start
	getvpn
	;;
test)
	firstnode=$(get_first_node)
	echo $firstnode
exit
	status=$(test_url "https://www.google.com/generate_204")
	echo $status
	exit
	;;
*)
	echo "No this function!"
	;;
esac
exit
