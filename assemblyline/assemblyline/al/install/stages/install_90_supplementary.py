#!/usr/bin/env python


def install(alsi):

    alsi.info("Installing supplementary packages.")
    alsi.sudo_apt_install(
        alsi.config['installation']['supplementary_packages']['apt']
    )
    alsi.pip_install_all(
        alsi.config['installation']['supplementary_packages']['pip']
    )
    alsi.info("Completed supplementary.")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
