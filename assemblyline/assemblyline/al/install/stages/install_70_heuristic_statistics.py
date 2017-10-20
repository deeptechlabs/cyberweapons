
from assemblyline.al.install import SiteInstaller


def install(alsi=None):
    alsi = alsi or SiteInstaller()

    alsi.milestone("Install heuristics statistics...")
    alsi.sudo_install_file('assemblyline/al/install/etc/cron/al-heuristics',
                          '/etc/cron.d/al-heuristics')
    alsi.milestone("Completed installation of heuristic statistics.")

if __name__ == '__main__':
    install()

