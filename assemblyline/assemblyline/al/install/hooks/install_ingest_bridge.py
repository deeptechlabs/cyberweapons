
import os


def execute(alsi):
    return install_ingest_bridge(alsi)


def install_ingest_bridge(alsi):
    alsi.sudo_install_file('assemblyline/al/install/etc/init/ingest_bridge.conf',
                          '/etc/init/ingest_bridge.conf')

    if not os.path.exists('/etc/init.d/ingest_bridge'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/ingest_bridge')


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install_ingest_bridge(installer)
