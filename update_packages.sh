#!/usr/bin/env bash

upgrade(){
    # Upgrade pip itself
    python -m pip install --upgrade pip

    # Upgrade all outdated packages
    pip list --format=freeze \
    | cut -d '=' -f1 \
    | xargs -n1 pip install --upgrade
}

remove_img(){
    docker image ls | awk -F' ' 'NR>1{print $3}' | xargs docker image rm
}

remove_container(){
    docker ps -a | awk -F ' ' 'NR>1{print $1}' | xargs docker rm
}

[[ $1 =~ '--help' || $1 =~ '-h' ]] && 
    echo "    Useage: ./update_packages.sh -u # For upgrading" &&
    echo "            ./update_packages.sh -r # For removing ALL docker Images" &&
    echo "            ./update_packages.sh -c # For removing ALL docker containers" &&
    exit $?

[[ $1 =~ '-u' ]] && upgrade && exit $?
[[ $1 =~ '-r' ]] && remove_img && exit $?
[[ $1 =~ '-c' ]] && remove_container && exit $?