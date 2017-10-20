
from assemblyline.al.install import SiteInstaller


def install(alsi=None):
    alsi = alsi or SiteInstaller()

    if alsi.config.get('monitoring', {}).get('harddrive', False):
        alsi.milestone("Install harddrive monitor...")
        alsi.sudo_install_file('assemblyline/al/install/etc/cron/al-harddrive_monitor',
                              '/etc/cron.d/al-harddrive_monitor')
        alsi.milestone("Completed installation of harddrive monitor.")

if __name__ == '__main__':
    install()

