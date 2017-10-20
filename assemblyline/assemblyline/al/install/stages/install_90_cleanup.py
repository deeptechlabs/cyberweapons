#!/usr/bin/env python

import os
EXEC_DUMP_PATH = "/usr/local/bin"


def install(alsi):
    install_service_all_script(alsi)
    install_git_pull(alsi)
    install_al_cli(alsi)
    install_switch_branch(alsi)

    alsi.info("Cleaning up installation directory")
    alsi.runcmd("sudo chown -R {user}:adm {root}".format(user=alsi.config['system']['user'],
                                                         root=alsi.config['system']['root']))
    alsi.info("Completed cleanup.")


def install_service_all_script(alsi):
    alsi.milestone('Create service all script')
    script_name = "al_service_all"

    script = os.path.join(alsi.alroot, "pkg/assemblyline/al/run/service_all.py")
    target = '/tmp/{script_name}'.format(script_name=script_name)

    alsi.runcmd('echo "#!/bin/sh\n\n'
                '[ \$# -lt 1 ] && echo \\"usage: {script_name} <action>\\" && exit 1\n\n'
                'python {script} \$1" > {target}'.format(script=script, target=target, script_name=script_name),
                raise_on_error=False)
    alsi.runcmd("chmod +x {target}".format(target=target))
    alsi.runcmd("sudo mv {target} {exec_path}/{script_name}".format(target=target,
                                                                    exec_path=EXEC_DUMP_PATH,
                                                                    script_name=script_name))


def install_git_pull(alsi):
    alsi.milestone('Create git pull script')
    script_name = "al_git_pull"

    user = alsi.config['system']['user']
    git_pull_path = os.path.join(alsi.alroot, 'pkg/assemblyline/al/run/git-pull.sh')
    target = '/tmp/{script_name}'.format(script_name=script_name)

    alsi.runcmd('echo "#!/bin/sh\n\nsudo su {user} -c {git_pull}" > {target}'.format(user=user,
                                                                                     git_pull=git_pull_path,
                                                                                     target=target),
                raise_on_error=False)
    alsi.runcmd("chmod +x {target}".format(target=target))
    alsi.runcmd("sudo mv {target} {exec_path}/{script_name}".format(target=target,
                                                                    exec_path=EXEC_DUMP_PATH,
                                                                    script_name=script_name))


def install_al_cli(alsi):
    alsi.milestone('Create al cli script')
    script_name = "al_cli"

    user = alsi.config['system']['user']
    invoke_path = os.path.join(alsi.alroot, 'pkg/assemblyline/al/run/invoke.sh')
    cli_path = os.path.join(alsi.alroot, 'pkg/assemblyline/al/run/cli.py')
    target = '/tmp/{script_name}'.format(script_name=script_name)

    alsi.runcmd('echo \'#!/bin/bash\n\n'
                'run_al_cli(){{\n'
                '    if [ $# = 0 ]; then\n'
                '        invoke="{invoke}"\n'
                '        args="$@"\n'
                '    else\n'
                '        invoke=". /etc/default/al && "\n'
                '        args=""\n'
                '        for i in "$@"; do\n'
                '            if [[ $i =~ \ + ]] ;then\n'
                '               args="$args \\"$i\\""\n'
                '            else\n'
                '               args="$args $i"\n'
                '            fi\n'
                '        done\n'
                '    fi\n'
                '    cli="{cli}"\n'
                '    sudo su {user} -c "${{invoke}} ${{cli}} ${{args}}"\n'
                '}}\n\n'
                'run_al_cli "$@"\n\' > {target}'.format(user=user, invoke=invoke_path, cli=cli_path, target=target),
                raise_on_error=False)
    alsi.runcmd("chmod +x {target}".format(target=target))
    alsi.runcmd("sudo mv {target} {exec_path}/{script_name}".format(target=target,
                                                                    exec_path=EXEC_DUMP_PATH,
                                                                    script_name=script_name))


def install_switch_branch(alsi):
    alsi.milestone('Create switch branch script')
    script_name = "al_switch_branch"

    user = alsi.config['system']['user']
    script = os.path.join(alsi.alroot, 'pkg/assemblyline/al/run/switch_branch.sh')
    target = '/tmp/{script_name}'.format(script_name=script_name)

    alsi.runcmd('echo \'#!/bin/sh\n\nsudo su {user} -c "{git_pull} $1"\' > {target}'.format(user=user,
                                                                                     git_pull=script,
                                                                                     target=target),
                raise_on_error=False)
    alsi.runcmd("chmod +x {target}".format(target=target))
    alsi.runcmd("sudo mv {target} {exec_path}/{script_name}".format(target=target,
                                                                    exec_path=EXEC_DUMP_PATH,
                                                                    script_name=script_name))


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
