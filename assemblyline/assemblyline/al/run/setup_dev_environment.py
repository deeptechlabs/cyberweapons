#!/usr/bin/env python

import os
import subprocess
import sys
import re

sys.path.append(os.path.realpath(__file__).replace('assemblyline/al/run/setup_dev_environment.py', ''))

if __name__ == "__main__":
    from assemblyline.al.install import SiteInstaller

    # noinspection PyBroadException
    try:
        proc = subprocess.Popen(["git", "remote", "-v"],
                                cwd=os.path.dirname(os.path.realpath(__file__)),
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        rem_stdout, _ = proc.communicate()
        proc = subprocess.Popen(["git", "branch"],
                                cwd=os.path.dirname(os.path.realpath(__file__)),
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        br_stdout, _ = proc.communicate()

        try:
            # Find the text between "origin" and "(fetch)"
            url = re.search("origin\t([^ ]*) \\(fetch\\)", rem_stdout).group(1)
        except AttributeError:
            print "Could not find origin fetch url in"
            print rem_stdout
            sys.exit(0)

        # Replace the last instance of "assemblyline" with "{repo}"
        url = re.sub("(.*/)assemblyline(.*?)", r"\1{repo}\2", url)

        try:
            # Find the first line that start with "* " and save everything after that
            branch = re.search("^\\* (.*)", br_stdout, re.MULTILINE).group(1)
        except AttributeError:
            print "Could not find current branch in"
            print br_stdout
            sys.exit(0)

        git_override = {
            'url': url,
            'branch': branch
        }
    except Exception, e:
        git_override = None

    args = sys.argv[1:]
    if not args:
        seed = 'assemblyline.al.install.seeds.assemblyline_common.DEFAULT_SEED'
    else:
        seed = args[0]

    ssi = SiteInstaller(seed=seed, simple=True)
    ssi.setup_git_repos(git_override=git_override)
