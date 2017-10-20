#!/usr/bin/env python

from assemblyline.al.install import SiteInstaller


def execute(alsi):
    return install_ui_symlinks(alsi)


def install_ui_symlinks(alsi):
    alsi.symlink('al_private/ui/static/images', 'al_ui/static/images/private')
    alsi.symlink('al_private/ui/static/js', 'al_ui/static/js/private')
    alsi.symlink('al_private/ui/static/ng-template', 'al_ui/static/ng-template/private')
    alsi.symlink('al_private/ui/templates', 'al_ui/templates/private')
    alsi.milestone("Private preinstall UI symlinks established")

if __name__ == '__main__':
    installer = SiteInstaller()
    install_ui_symlinks(installer)
