#!/bin/bash

location_bin=$(which rss.py)
[ -z "${location_bin}" ] && [ -f ./rss.py ] && location_bin="./rss.py"
commands=$( grep add_argument ${location_bin} | awk -F'(' '{print $2}' | tr -d ["'"] | tr [','] ['\n'] | awk '/^-/ {print $0}' | xargs )
[ -z "${commands}" ]  && return
complete -D -W "${commands}" -p rss.py
complete -D -W "${commands}" -p ./rss.py
complete -D -W "${commands}" -p -P python rss.py
echo "rss.py will be completed with ${commands}"