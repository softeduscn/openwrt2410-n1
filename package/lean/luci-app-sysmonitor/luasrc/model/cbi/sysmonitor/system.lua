
local m, s
local global = 'sysmonitor'
local uci = luci.model.uci.cursor()
ip = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh getip")

m = Map("sysmonitor",translate("System Settings"))
m:append(Template("sysmonitor/status"))

n = Map("sysmonitor",translate(""))
n:append(Template("sysmonitor/service"))

s = n:section(TypedSection, "sysmonitor", translate(""))
s.anonymous = true

--o=s:option(Flag,"enable", translate("Enable"))
--o.rmempty=false

--[[
o = s:option(Value, "vpn", translate("Select VPN"))
if nixio.fs.access("/etc/init.d/openclash") then
o:value("Openclash")
end
if nixio.fs.access("/etc/init.d/shadowsocksr") then
o:value("Shadowsocksr")
end
if nixio.fs.access("/etc/init.d/passwall2") then
o:value("Passwall2")
end
if nixio.fs.access("/etc/init.d/passwall") then
o:value("Passwall")
end
o:value("NULL", translate("NULL"))
o.default = "Shadowsocksr"
o.rmempty = false

o = s:option(Value, "dns", translate("Select DNS"))
if nixio.fs.access("/etc/init.d/mosdns") then
o:value("MosDNS")
end
if nixio.fs.access("/etc/init.d/smartdns") then
o:value("SmartDNS")
end
o:value("NULL", translate("NULL"))
o.default = "MosDNS"
o.rmempty = false

--o = s:option(Value, "smartdnsPORT", translate("SmartDNS PORT"))
--o:value("6053")
--o.default = "6053"
--o:depends("dns", "SmartDNS")
--]]

o = s:option(Value, "gateway", translate("Gateway Address"))
--o.description = translate("IP for gateway(192.168.1.1)")
--o:value("192.168.1.1")
o.default = "192.168.1.1"
o.datatype = "or(host)"
o.rmempty = false

--o = s:option(Value, "ipaddr", translate("Lan Address"))
--o:value("192.168.1.110")
--o.default = "192.168.1.110"
--o.datatype = "or(host)"
--o.rmempty = false

o = s:option(DynamicList, "dnslist", translate("DNS List"))
o.datatype = "or(host)"
o.rmempty = true

local apply = luci.http.formvalue("cbi.apply")
if apply then
	luci.sys.exec("touch /tmp/network.sign")
end

return m, n
