
local m

m = Map("sysmonitor",translate("General Settings"))

s = m:section(TypedSection, "sysmonitor")
s.anonymous = true

o = s:option(Value, "systime", translate("Check system time(s)"))
o.rmempty = false

o = s:option(Value, "nextvpntime", translate("Switch VPN time(m)"))
o.rmempty = false

o = s:option(Value, "chkprog", translate("Check delay_prog time(s)"))
o.rmempty = false

o = s:option(Value, "mosdns_port", translate("MosDNS listen port"))
o.rmempty = false

o = s:option(Value, "local_port", translate("SmartDNS local port"))
o.rmempty = false

o = s:option(Value, "oversea_port", translate("SmartDNS oversea port"))
o.rmempty = false

o = s:option(Value, "oversea", translate("SmartDNS oversea para"))
o.rmempty = false

o = s:option(Value, "firmware", translate("Download firmware url"))
o.rmempty = false

o = s:option(Value, "mosdns_url", translate("Update Mosdns-data url"))
o.rmempty = false

local apply = luci.http.formvalue("cbi.apply")
if apply then
    luci.sys.exec("echo '10=/usr/share/sysmonitor/sysapp.sh setdns_port' >> /tmp/delay.sign")
end
return m
