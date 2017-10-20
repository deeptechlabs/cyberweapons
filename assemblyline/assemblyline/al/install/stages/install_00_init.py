#!/usr/bin/env python

from assemblyline.al.install import SiteInstaller


def install(alsi=None):
    import getpass
    alsi = alsi or SiteInstaller()
    user = alsi.config['system']['user']
    password = alsi.config['system'].get('password', None)
    root = alsi.config['system']['root']
    alsi.info("Creating user: [{user}]".format(user=user))
    if password:
        # noinspection PyUnresolvedReferences
        import crypt
        crypt_pass = crypt.crypt(password, "%s_%s_%s" % (user, root, password))
        alsi.runcmd('sudo useradd -d {root} -p {crypt_pass} {user}'.format(user=user,
                                                                          root=root,
                                                                          crypt_pass=crypt_pass),
                   raise_on_error=False)
    else:
        alsi.runcmd('sudo useradd -d {root} {user}'.format(user=user, root=root), raise_on_error=False)

    alsi.info("Making sure current user can write into the install directory")
    alsi.runcmd("sudo chown -R {user}:adm {root}".format(user=getpass.getuser(),
                                                        root=root))
    alsi.info("Completed cleanup.")

if __name__ == '__main__':
    install()
