--local datatypes = require "luci.cbi.datatypes"

local name = string.gsub(luci.sys.exec("uci get sysmonitor.sysmonitor.datalist"),"^%s*(.-)%s*$","%1")
local list_file = string.gsub( luci.sys.exec("/usr/share/sysmonitor/sysapp.sh getdata "..name.." path"),"^%s*(.-)%s*$","%1")

f = Map("sysmonitor")
f:append(Template("sysmonitor/data"))

m = Map("sysmonitor")
s = m:section(TypedSection, "sysmonitor", translate("Rule Settings"))
s.anonymous = true

s:tab("list", translate(name))
o = s:taboption("list", TextValue, "", "", "")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section) return nixio.fs.readfile(list_file) or "" end
o.write = function(self, section, value) nixio.fs.writefile(list_file , value:gsub("\r\n", "\n")) end
o.remove = function(self, section, value) nixio.fs.writefile(list_file , "") end
o.validate = function(self, value)
    return value
end

--local apply = luci.http.formvalue("cbi.apply")
--if apply then
--    luci.sys.exec("/etc/init.d/mosdns reload")
--end
return f,m
