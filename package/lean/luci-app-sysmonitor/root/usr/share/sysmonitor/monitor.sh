#!/bin/bash

NAME=sysmonitor
APP_PATH=/usr/share/$NAME

[ "$(uci get sysmonitor.sysmonitor.enable)" == 0 ] && exit
[ "$(pgrep -f sysmonitor.sh|wc -l)" == 0 ] && echo 0 > /tmp/sysmonitor.pid
[ -f /tmp/sysmonitor.run ] && exit
$APP_PATH/sysmonitor.sh &
