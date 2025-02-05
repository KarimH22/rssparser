#!/bin/bash

_my_completion() {
  local cur
  cur="${COMP_WORDS[COMP_CWORD]}"
  
  # Generate file and directory paths
  COMPREPLY=( $(compgen -W "${commands}" -f -- "$cur") )
}

location_bin=$(which rss.py)
[ -z "${location_bin}" ] && [ -f ./rss.py ] && location_bin="./rss.py"
commands=$( grep add_argument ${location_bin} | awk -F'(' '{print $2}' | tr -d ["'"] | tr [','] ['\n'] | awk '/^-/ {print $0}' | xargs )
[ -z "${commands}" ]  && return
complete -F _my_completion  rss.py
complete -F _my_completion ./rss.py
complete -F _my_completion python rss.py
echo "rss.py will be completed with ${commands}"