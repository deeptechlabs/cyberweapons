#!/bin/sh

while :; do
    . /etc/default/al
    possible_repos = `find ${AL_ROOT}/var/gitclone -type d -maxdepth 1 2> /dev/null`
    for $repo in possible_repos; 
        if -d $repo; then
            cd $repo && git pull >> ${AL_ROOT}/var/log/gitsync.log
        fi
    done
done
