#!/bin/bash

list_required_pip_package="feedparser validators lxml"

list_required_apt_package="python3-lxml python3-validators python3-feedparser"

SUDO=
[ -x /usr/bin/sudo ] && SUDO=/usr/bin/sudo
package_install_result=0

install_with_apt()
{
    set +e
    ${SUDO} apt update
    for pack in ${list_required_apt_package}
    do
        apt list --installed | egrep "\b${pack}\b"
        [ $? -eq 0  ]  && continue
        ${SUDO} apt install -y ${pack}
        package_install_result=$(expr $? + ${package_install_result} )
    done    
    set -e
    
}

usage_pip(){
    echo "you need to install with pip"
    echo "Please create your pip env"
    echo "apt install -y python3-venv"
    echo "python3 -m venv $HOME/envdir"
    echo "export VIRT_PYTHON_DIR=$HOME/envdir"
    echo -e "and run \n . ./install_deps.sh \n install_with_pip"
}

install_with_pip()
{
    ${VIRT_PYTHON_DIR}/bin/python -m pip  install -y ${list_required_pip_package}
}

################################
##### MAIN
###############################
install_with_apt
[ ${package_install_result} -ne 0 ] &&  usage_pip