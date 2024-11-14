nextvpn=luci.sys.exec("uci get sysmonitor.sysmonitor.nextvpn")
urlchk=luci.sys.exec("uci get sysmonitor.sysmonitor.urlchk")
testchk=luci.sys.exec("uci get sysmonitor.sysmonitor.testchk")
m = Map("sysmonitor",translate("VPN Nodes"))
s = m:section(TypedSection, "sysmonitor", "")
if tonumber(nextvpn) == 1 then
	box=' <input type="checkbox" checked="checked" />'
	check='Disable switch VPN'
else
	box=' <input type="checkbox" />'
	check='Enable switch VPN'	
end
if tonumber(urlchk) == 1 then
	vpn=' <input type="checkbox" checked="checked" />'
	checkvpn='Disable URL check VPN'
else
	vpn=' <input type="checkbox" />'
	checkvpn='Enable URL check VPN'	
end
if tonumber(testchk) == 1 then
	testvpn=' <input type="checkbox" checked="checked" />'
	testcheckvpn='Disable TEST check VPN'
else
	testvpn=' <input type="checkbox" />'
	testcheckvpn='Enable TEST check VPN'	
end

s.description = '<button class="button1" title="Set switch VPN mode"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=VPNswitch&sys1=&redir=node">'..translate(check)..'</a></button>'..box..' <button class="button1" title="Set URL check VPN mode"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=URLchkVPN&sys1=&redir=node">'..translate(checkvpn)..'</a></button>'..vpn..' <button class="button1" title="Set TEST check VPN mode"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=TESTchkVPN&sys1=&redir=node">'..translate(testcheckvpn)..'</a></button>'..testvpn
s.anonymous = true

f = SimpleForm("sysmonitor")
f.reset = false
f.submit = false
f:append(Template("sysmonitor/node"))
return m,  f
