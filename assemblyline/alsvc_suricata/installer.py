#!/usr/bin/env python

import os


def install(alsi):
    alsi.sudo_apt_install([
        'oinkmaster',
        'libpcre3',
        'libpcre3-dbg',
        'libpcre3-dev',
        'build-essential',
        'autoconf',
        'automake',
        'libtool',
        'libpcap-dev',
        'libnet1-dev',
        'libyaml-0-2',
        'libyaml-dev',
        'zlib1g',
        'zlib1g-dev',
        'libcap-ng-dev',
        'libcap-ng0',
        'make',
        'libmagic-dev',
        'libjansson-dev',
        'libjansson4',
        'pkg-config'
    ])

    alsi.pip_install_all(['simplejson', 'python-dateutil'])

    directories = [
        '/etc/suricata',
        '/etc/suricata/rules',
        '/var/log/suricata'
    ]

    if not os.path.exists("/usr/local/bin/suricata"):
        src = 'suricata-3.1.2.tar.gz'
        remote_path = os.path.join('suricata/' + src)
        local_path = os.path.join('/tmp/', src)

        # Grab Suricata from the package repo
        alsi.fetch_package(remote_path, local_path)

        # Configure and build Suricata
        alsi.runcmd('sudo tar -C /tmp/ -xzf ' + local_path)
        src_path = local_path[:-7]
        alsi.runcmd('cd %s && sudo ./configure --prefix=/usr/local/ --sysconfdir=/etc/ --localstatedir=/var/ '
                   '&& sudo make -C %s && sudo make -C %s install && sudo ldconfig' % (src_path, src_path, src_path))
        alsi.runcmd('sudo rm -rf %s %s' % (src_path, local_path))

    # Create directories
    for directory in directories:
        alsi.runcmd('sudo mkdir -p  %s' % directory)
        alsi.runcmd('sudo chown -R %s %s' % (alsi.config['system']['user'], directory))

    alsi.runcmd('sudo cp %s %s' %
               (os.path.join(alsi.alroot, 'pkg', 'al_services', 'alsvc_suricata', 'conf', 'suricata.yaml'),
                '/etc/suricata/'))
    alsi.runcmd('sudo chown %s /etc/suricata/suricata.yaml' % alsi.config['system']['user'])

    # Copy the Suricata configuration into position
    home_net = alsi.config['services']['master_list']['Suricata']['config']['HOME_NET']
    home_net = home_net.replace('/', '\/').replace('[', '\[').replace(']', '\]')
    alsi.sudo_sed_inline('/etc/suricata/suricata.yaml', ['s/__HOME_NET__/{home_net}/g'.format(home_net=home_net)])

    rules_urls = alsi.config['services']['master_list']['Suricata']['config']['RULES_URLS']

    # Update our local rules using Oinkmaster
    rules_command = ["sudo", "/usr/sbin/oinkmaster", "-Q", "-o", "/etc/suricata/rules"]
    for rules_url in rules_urls:
        rules_command.extend(["-u",
                              rules_url.replace('/', '\/').replace('[', '\[').replace(']', '\]').replace(':', '\:')])
    alsi.runcmd(" ".join(rules_command))

    alsi.runcmd("sudo touch /etc/suricata/oinkmaster")
    alsi.runcmd('sudo chown -R %s /etc/suricata/rules' % alsi.config['system']['user'])
    alsi.runcmd('sudo chown %s /etc/suricata/oinkmaster' % alsi.config['system']['user'])

    # Build stripe, a tool to strip frame headers from PCAP files
    if not os.path.exists("/usr/local/bin/stripe"):
        stripe_path = os.path.join(alsi.alroot, 'pkg', 'al_services', 'alsvc_suricata', "stripe")
        alsi.runcmd('/usr/bin/gcc -o %s %s' % (os.path.join(stripe_path, 'stripe'), os.path.join(stripe_path, 'stripe.c')))
        alsi.runcmd('sudo cp %s %s' % (os.path.join(stripe_path, 'stripe'), '/usr/local/bin/stripe'))

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller

    install(SiteInstaller())
