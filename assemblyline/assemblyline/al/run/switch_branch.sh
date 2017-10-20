#!/bin/sh

[ $# -lt 1 ] && echo "usage: al_switch_branch <branch>" && exit 1

. /etc/default/al

switch_branch() {
    repo_path=$1
    repo=$2
    branch=$3
    if [ -d ${repo_path} ]; then
        cur_branch=`cd ${repo_path} && git branch | grep "*" | tr -d "* "`
        echo "Switching ${repo} to branch $branch:"
        (cd ${repo_path} &&
         git fetch --all &&
         git reset --hard origin/${cur_branch} 2> /dev/null 1> /dev/null &&
         git checkout ${branch} &&
         git reset --hard origin/${branch}) 2>&1 |
        grep -Ev '^(Already on|Your branch is up-to-date with) ' |
        grep -Ev '^Fetching origin$' |
        sed -e "s|HEAD is||g" -e 's|^|\t|g'
        echo
    fi
}

for repo_path in ${PYTHONPATH}/*;
do
    repo=`echo ${repo_path} | sed -e "s|${PYTHONPATH}/||g"`
    if [ $repo != "al_services" ]; then
        switch_branch ${repo_path} ${repo} ${1}
    fi
done

for repo_path in ${PYTHONPATH}/al_services/*;
do
    repo=`echo ${repo_path} | sed -e "s|${PYTHONPATH}/al_services/||g"`
    switch_branch ${repo_path} ${repo} ${1}
done
