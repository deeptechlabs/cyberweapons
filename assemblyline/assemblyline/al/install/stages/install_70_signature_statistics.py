
from assemblyline.al.install import SiteInstaller


def install(alsi=None):
    alsi = alsi or SiteInstaller()

    alsi.milestone("Install signature statistics...")
    alsi.sudo_install_file('assemblyline/al/install/etc/cron/al-signatures',
                          '/etc/cron.d/al-signatures')
    alsi.milestone("Completed installation of signature statistics.")

if __name__ == '__main__':
    install()

