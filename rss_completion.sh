#!/bin/bash

location_bin=$(which rss.py)
[ -z "${location_bin}" ] && [ -f ./rss.py ] && location_bin="./rss.py"
commands=$( grep add_argument ${location_bin} | awk -F'(' '{print $2}' | tr -d ["'"] | tr [','] ['\n'] | awk '/^-/ {print $0}' | xargs )
[ -z "${commands}" ]  && return
complete -W "${commands}" rss.py
complete -W "${commands}" ./rss.py
complete -W "${commands}" python rss.py
echo "rss.py will be completed with ${commands}"