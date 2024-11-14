-- Copyright (C) 2017
-- Licensed to the public under the GNU General Public License v3.

module("luci.controller.sysmonitor", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/sysmonitor") then
		return
	end
	entry({"admin", "sys"}, firstchild(), "SYS", 10).dependent = false
	entry({"admin", "sys","sysmonitor"}, alias("admin", "sys","sysmonitor", "system"),_("SYSMonitor"), 10).dependent = true
	entry({"admin", "sys", "sysmonitor", "system"}, cbi("sysmonitor/system"),_("System Settings"), 20).leaf = true
	entry({"admin", "sys", "sysmonitor", "general"}, cbi("sysmonitor/general"),_("General Settings"), 30).leaf = true
	entry({"admin", "sys", "sysmonitor", "prog"},cbi("sysmonitor/prog"),_("PROG"), 40).leaf = true
	entry({"admin", "sys", "sysmonitor", "node"},cbi("sysmonitor/node"),_("NODE"), 41).leaf = true
--	entry({"admin", "sys", "sysmonitor", "ddns"}, cbi("/sysmonitor/ddns"), _("DDNS"), 50).leaf = true
	entry({"admin", "sys", "sysmonitor", "host"},cbi("sysmonitor/host"),_("Host"), 60).leaf = true
	entry({"admin", "sys", "sysmonitor", "wgusers"},cbi("sysmonitor/wgusers"),_("WGusers"), 75).leaf = true
	entry({"admin", "sys", "sysmonitor", "data"},cbi("sysmonitor/data"),_("DATA List"), 80).leaf = true
	entry({"admin", "sys", "sysmonitor", "log"},cbi("sysmonitor/log"),_("Log"), 90).leaf = true

	entry({"admin", "sys", "sysmonitor", "ip_status"}, call("action_ip_status")).leaf = true
	entry({"admin", "sys", "sysmonitor", "wireguard_status"}, call("action_wireguard_status")).leaf = true
	entry({"admin", "sys", "sysmonitor", "vpns_status"}, call("action_vpns_status")).leaf = true
	entry({"admin", "sys", "sysmonitor", "prog_status"}, call("action_prog_status"))
	entry({"admin", "sys", "sysmonitor", "service_button"}, call("service_button")).leaf = true
	entry({"admin", "sys", "sysmonitor", "proglist"}, call("proglist"))
	entry({"admin", "sys", "sysmonitor", "datalist"}, call("datalist"))
	entry({"admin", "sys", "sysmonitor", "firmware"}, call("firmware"))
	entry({"admin", "sys", "sysmonitor", "stopDL"}, call("stopDL"))
	entry({"admin", "sys", "sysmonitor", "sysupgrade"}, call("sysupgrade"))
	entry({"admin", "sys", "sysmonitor", "sysmenu"}, call("sysmenu"))

	entry({"admin", "sys", "sysmonitor", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "sys", "sysmonitor", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "sys", "sysmonitor", "node_info"}, call("node_info")).leaf = true
	entry({"admin", "sys", "sysmonitor", "wg_users"}, call("wg_users")).leaf = true
	
end

function action_ip_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		ip_title = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton lantitle");
		ip_state = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton lan")
	})
end

function action_vpns_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		vpns_title=luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton vpntitle");
		vpns_state=luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton vpn")
	})
end

function action_wireguard_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		wireguard_title = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton wg_title");
		wireguard_state = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton wg_state")
	})
end

function service_button()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		button_title=luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton buttontitle");
		button_state=luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton button")
	})
end

function get_log()
	luci.http.write(luci.sys.exec("[ -f '/var/log/sysmonitor.log' ] && cat /var/log/sysmonitor.log"))
end

function clear_log()
	luci.sys.exec("echo '' > /var/log/sysmonitor.log")
	luci.http.redirect(luci.dispatcher.build_url("admin", "sys", "sysmonitor","log"))
end

function node_info()
	luci.http.write(luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton node_list"))
end

function wg_users()
	luci.http.write(luci.sys.exec("[ -f '/var/log/wg_users' ] && cat /var/log/wg_users"))
end

function action_prog_status()
	luci.http.prepare_content("application/json")
	luci.http.write_json({
		prog_state = luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton prog")
	})
end

function proglist()
	luci.http.write(luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton prog_list"))
end

function datalist()
	luci.http.write(luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysbutton data_list"))
end

function sysmenu()
	sys=luci.http.formvalue("sys")
	sys1=luci.http.formvalue("sys1")
	redir=luci.http.formvalue("redir")
	luci.http.redirect(luci.dispatcher.build_url("admin", "sys", "sysmonitor", redir))
	luci.sys.exec("/usr/share/sysmonitor/sysapp.sh sysmenu "..sys.." "..sys1)
end
