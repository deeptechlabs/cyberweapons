#!/bin/sh

. /etc/default/al

git_update() {
    repo_path=$1
    repo=$2
    if [ -d ${repo_path} ]; then
        branch=`cd ${repo_path} && git branch | grep "*" | tr -d "* "`
        echo "Updating ${repo} ($branch):"
        (cd ${repo_path} &&
         git fetch --all &&
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
        git_update ${repo_path} ${repo}
    fi
done

for repo_path in ${PYTHONPATH}/al_services/*;
do
    repo=`echo ${repo_path} | sed -e "s|${PYTHONPATH}/al_services/||g"`
    git_update ${repo_path} $repo
done
