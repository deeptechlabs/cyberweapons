import json
import os
import logging
import platform
import subprocess
import sys
import time

from urllib import quote
from urlparse import urlparse

from assemblyline.al.common.service_utils import get_merged_svc_config
from assemblyline.al.common.transport import ftp, local, http
from assemblyline.common.importing import module_attribute_by_name

logging.basicConfig(stream=sys.stderr, level=logging.INFO)


NODETYPE_CORE = 'core'
NODETYPE_RIAK = 'riak'
NODETYPE_WORKER = 'worker'


class PackageFetcher(object):

    TYPE_FTP = 'ftp'
    TYPE_SFTP = 'sftp'
    TYPE_HTTP = 'http'
    TYPE_LOCAL = 'local'
    TYPE_S3 = 's3'
    VALID_TYPES = [TYPE_FTP, TYPE_LOCAL, TYPE_S3, TYPE_SFTP, TYPE_HTTP]

    def __init__(self, config, alsi):
        if not config:
            raise Exception("Missing or invalid configuration for external_packages.")
        self._transports = {}

        self.cfg = config
        print "========\n= PackageFetcher endpoints"
        for realm, realm_cfg in self.cfg.iteritems():
            transport_type = realm_cfg['transport']
            if transport_type not in self.VALID_TYPES:
                raise Exception("Invalid package transport type: %s" % transport_type)

            if transport_type == self.TYPE_FTP:
                ftpargs = realm_cfg['args']
                self._transports[realm] = ftp.TransportFTP(
                    base=ftpargs['base'], host=ftpargs['host'],
                    password=ftpargs['password'], user=ftpargs['user'])
                print "[{realm}]\n{type}://{user}:{password}@{host}{base}".format(realm=realm,
                                                                                  type=self.TYPE_FTP,
                                                                                  user=ftpargs['user'],
                                                                                  password=ftpargs['password'],
                                                                                  host=ftpargs['host'],
                                                                                  base=ftpargs['base'])
            elif transport_type == self.TYPE_SFTP:
                try:
                    from assemblyline.al.common.transport import sftp
                except ImportError:
                    alsi.milestone("Installing SFTP transport dependancies")
                    alsi.sudo_apt_install("python-pip")
                    alsi.pip_install_all(['setuptools==24.0.2', 'paramiko==2.0.1', 'pysftp==0.2.9'])
                    from assemblyline.al.common.transport import sftp

                sftpargs = realm_cfg['args']
                self._transports[realm] = sftp.TransportSFTP(**sftpargs)
                out = "[{realm}]\n{type}://".format(realm=realm, type=self.TYPE_SFTP)
                if 'user' in sftpargs and 'password' in sftpargs:
                    out += "{user}:{password}@".format(user=sftpargs['user'], password=sftpargs['password'])
                out += "{host}{base}".format(host=sftpargs['host'], base=sftpargs['base'])
                first_param = True
                for k in ["private_key", "validate_host", "private_key_pass"]:
                    if k in sftpargs:
                        if first_param:
                            out += "?{key}={val}".format(key=k, val=sftpargs[k])
                        else:
                            out += "&{key}={val}".format(key=k, val=sftpargs[k])
                print out
            elif transport_type == self.TYPE_HTTP:
                httpargs = realm_cfg['args']
                self._transports[realm] = http.TransportHTTP(**httpargs)
                out = "[{realm}]\n{type}://".format(realm=realm, type=self.TYPE_HTTP)
                if 'user' in httpargs and 'password' in httpargs:
                    out += "{user}:{password}@".format(user=httpargs['user'], password=httpargs['password'])
                out += "{host}{base}".format(host=httpargs['host'], base=httpargs['base'])
                first_param = True
                for k in ["pki"]:
                    if k in httpargs:
                        if first_param:
                            out += "?{key}={val}".format(key=k, val=httpargs[k])
                        else:
                            out += "&{key}={val}".format(key=k, val=httpargs[k])
                print out
            elif transport_type == self.TYPE_LOCAL:
                base_dir = realm_cfg['args']['base']
                self._transports[realm] = local.TransportLocal(base=base_dir)
                print "[{realm}]\n{type}://{base}".format(realm=realm, type=self.TYPE_LOCAL, base=base_dir)
            elif transport_type == self.TYPE_S3:
                try:
                    from assemblyline.al.common.transport import s3
                except ImportError:
                    alsi.milestone("Installing Amazon S3 Dependencies...")
                    alsi.sudo_apt_install("python-pip")
                    alsi.pip_install_all(["boto3==1.4.4", 'botocore==1.5.62'])
                    from assemblyline.al.common.transport import s3
                logging.getLogger('botocore').setLevel(logging.WARNING)
                logging.getLogger('boto3').setLevel(logging.WARNING)
                s3args = realm_cfg['args']
                self._transports[realm] = s3.TransportS3(**s3args)
                print "[{realm}]\n{type}://{accesskey}:{secretkey}" \
                      "@{host}/{s3_bucket}".format(realm=realm,
                                                   type=self.TYPE_S3,
                                                   accesskey=s3args['accesskey'],
                                                   secretkey=s3args['secretkey'],
                                                   s3_bucket=s3args['s3_bucket'],
                                                   base=s3args['base'],
                                                   host=s3args.get('host', s3.TransportS3.DEFAULT_HOST))
            else:
                raise Exception("Transport not implemented: %s" % transport_type)
        print "========"

    def fetch(self, relpath, localpath, realm='assemblyline'):
        return self._transports[realm].download(relpath, localpath)


class SiteInstaller(object):

    def __init__(self, seed=None, simple=False):
        if not seed:
            seed = os.environ.get('AL_SEED', None)

        self.log = logging.getLogger('assemblyline.install')
        self.initial_seed = seed

        self.config = None
        self.seed_module = None
        self.reload_config()

        if self.config['system'].get('shell_bypass', False):
            SiteInstaller.runcmd("sudo ln -s /bin/sh /tmp/notashell", raise_on_error=False)
            self.shell = "/tmp/notashell"
        else:
            self.shell = "sh"
        self.alroot = self.config['system']['root']

        # cheap logging hooks for now
        self.info = self.log.info
        self.error = self.log.error
        self.warn = self.log.warn
        self.exception = self.log.exception

        if not simple:
            self._pipper = PipInstaller(pypi_index_url=self.config['installation']['pip_index_url'])
            self._package_fetcher = PackageFetcher(self.config['installation']['external_packages'], self)
            self.install_temp = os.path.join(self.alroot, 'var/.installtmp')
            if not os.path.exists(self.install_temp):
                os.makedirs(self.install_temp)
        else:
            self.install_temp = "/tmp"
            self._package_fetcher = None
            self._pipper = None

    def reload_config(self):
        self.seed_module = None
        if isinstance(self.initial_seed, dict):
            self.config = self.initial_seed
        elif self.initial_seed:
            self.config = module_attribute_by_name(self.initial_seed)
            self.seed_module = self.initial_seed
            services_to_register = self.config['services']['master_list']

            for service, svc_detail in services_to_register.iteritems():
                self.config['services']['master_list'][service] = get_merged_svc_config(service, svc_detail, self.log)
        else:
            from assemblyline.al.common import config_riak
            self.config = config_riak.load_seed()

    def fatal(self, s):
        def red(st):
            prefix = '\x1b[' + '31m'
            suffix = '\x1b[0m'
            return prefix + st + suffix
        self.log.error(red(s))

    def get_nodetypes_from_seed(self):
        types = []
        # noinspection PyBroadException
        try:
            ip = self.get_ipaddress()
            hostname = self.get_hostname()
        except:
            ip = "127.0.0.1"
            hostname = "localhost"

        if ip in self.config['core']['nodes'] or \
                hostname in self.config['core']['nodes'] or \
                'localhost' in self.config['core']['nodes'] or \
                '127.0.0.1' in self.config['core']['nodes']:
            types.append(NODETYPE_CORE)

        if ip in self.config['datastore']['riak']['nodes'] or \
                hostname in self.config['datastore']['riak']['nodes'] or \
                'localhost' in self.config['datastore']['riak']['nodes'] or \
                '127.0.0.1' in self.config['datastore']['riak']['nodes']:
            types.append(NODETYPE_RIAK)

        if ip in self.config['workers']['nodes'] or \
                hostname in self.config['workers']['nodes'] or \
                'localhost' in self.config['workers']['nodes'] or \
                '127.0.0.1' in self.config['workers']['nodes']:
            types.append(NODETYPE_WORKER)

        return types

    def setup_git_repos(self, root_git_list=None, site_specific_git_list=None, service_git_list=None,
                        git_override=None):
        install_dir = os.path.realpath(__file__).split(os.path.join('assemblyline', 'al', 'install'))[0]
        installation = self.config['installation']
        site_spec = self.config['sitespecific']
        services = self.config['services']['master_list']
        internal_repo = None

        if NODETYPE_CORE not in self.get_nodetypes_from_seed():
            internal_repo = self.config['system']['internal_repository']

        if root_git_list is None:
            root_git_list = installation.get('repositories', {}).get('repos', {}).keys()
        if site_specific_git_list is None:
            site_specific_git_list = site_spec.get('repositories', {}).keys()
        if service_git_list is None:
            service_git_list = services.keys()
            if not os.path.exists(os.path.join(install_dir, "al_services")):
                os.makedirs(os.path.join(install_dir, "al_services"))
                open(os.path.join(install_dir, "al_services", "__init__.py"), 'a').close()

        realm_urls = {}
        realm_branchs = {}
        for name, realm in installation.get('repositories', {}).get('realms', {}).iteritems():
            if git_override:
                realm_urls[name] = git_override['url']
                realm_branchs[name] = git_override['branch']
            elif internal_repo:
                realm_url = internal_repo['url']
                if not realm_url.endswith("/"):
                    realm_url += "/"

                realm_urls[name] = realm_url + "{repo}"
                realm_branchs[name] = internal_repo['branch']
            else:
                if realm['url'].lower().startswith("http"):
                    if realm['user'] and realm['password']:
                        scheme, url = realm['url'].split('://', 1)
                        realm_url = "%s://%s:%s@%s" % (scheme, realm['user'], quote(realm['password']), url)
                    else:
                        realm_url = realm['url']
                elif realm['url'].lower().startswith("git") or realm['url'].lower().startswith("ssh"):
                    if realm['key']:
                        ssh_dir = os.path.expanduser("~/.ssh/")
                        if not os.path.exists(os.path.join(ssh_dir, name)):
                            with open(os.path.join(ssh_dir, name), 'wb') as realm_pub_file:
                                realm_pub_file.write(realm['key'])

                        ssh_config = os.path.join(ssh_dir, 'config')
                        host, url = realm['url'][4:].split(":", 1)
                        if not self.grep_quiet(ssh_config, "HostName %s" % host, sudo=False):
                            config_block = "Host %s\n\tHostName %s\n\tUser git\n\tIdentityFile ~/.ssh/%s" % (name,
                                                                                                             host,
                                                                                                             name)
                            self.runcmd('echo "' + config_block + '" >> ' + ssh_config)

                    realm_url = realm['url']
                elif os.path.exists(realm['url']):
                    # Local git path
                    realm_url = realm['url']
                else:
                    self.fatal("Invalid realm %s:\n%s" % (name, str(realm)))
                    exit(1)

                if not realm_url.endswith("/"):
                    realm_url += "/"

                realm_urls[name] = realm_url + "{repo}.git"
                realm_branchs[name] = realm['branch']

        for repo in root_git_list:
            repo_realm = installation.get('repositories', {}).get('repos', {}).get(repo, {}).get('realm', {})
            if repo_realm:
                self._clone_or_seturl(repo, realm_urls[repo_realm], realm_branchs[repo_realm], install_dir)

        for svc in service_git_list:
            service = services.get(svc, {})
            repo = service.get('repo', None)
            if internal_repo:
                repo = "al_services/" + repo
            repo_realm = service.get('realm', None)
            if repo and repo_realm:
                self._clone_or_seturl(repo,
                                      realm_urls[repo_realm],
                                      realm_branchs[repo_realm],
                                      os.path.join(install_dir, "al_services"))
                if 'depends' in service:
                    depend_repo = service['depends'].get('repo', None)
                    if internal_repo:
                        depend_repo = "al_services/" + depend_repo
                    depend_realm = service['depends'].get('realm', None)
                    if depend_repo and depend_realm:
                        self._clone_or_seturl(depend_repo,
                                              realm_urls[depend_realm],
                                              realm_branchs[depend_realm],
                                              os.path.join(install_dir, "al_services"))

        for repo in site_specific_git_list:
            repo_realm = site_spec.get('repositories', {}).get(repo, {}).get('realm', {})
            if repo_realm:
                self._clone_or_seturl(repo, realm_urls[repo_realm], realm_branchs[repo_realm], install_dir)

    def _clone_or_seturl(self, repo, realm_url, branch, location):
        if os.path.exists(os.path.join(location, repo)):
            cmd = "git remote set-url origin %s" % realm_url.format(repo=repo)
            self.runcmd(cmd, shell=True, cwd=os.path.join(location, repo), raise_on_error=False)

            cmd = "git checkout %s" % branch
            self.runcmd(cmd, shell=True, cwd=os.path.join(location, repo), raise_on_error=False)

            cmd = "git pull"
            self.runcmd(cmd, shell=True, cwd=os.path.join(location, repo), raise_on_error=False)
        else:
            cmd = "git clone %s -b %s" % (realm_url.format(repo=repo), branch)
            self.runcmd(cmd, shell=True, cwd=location, raise_on_error=False)

    def install_persistent_pip_conf(self):
        # only necessary if we have an explicit pip configuration 
        pip_url = self.config['installation']['pip_index_url']
        if not pip_url:
            self.milestone("No explicit pip configuration specified")
            return

        self.milestone("Updating pip configuration files to point to %s" % pip_url)

        pip_dir = os.path.expanduser('~/.pip/')
        if not os.path.exists(pip_dir):
            os.makedirs(pip_dir)

        with open(os.path.join(pip_dir, 'pip.conf'), 'wb') as piprc:
            piprc.write("[global]\n")
            piprc.write("index-url=%s\n" % pip_url)

        with open(os.path.expanduser("~/.pydistutils.cfg"), 'wb') as pydistutils:
            pydistutils.write("[easy_install]\n")
            pydistutils.write("index-url=%s\n" % pip_url)

        self.runcmd("sudo mkdir /root/.pip/", raise_on_error=False)
        self.runcmd("sudo cp %s /root/.pip/pip.conf" % os.path.join(pip_dir, 'pip.conf'))
        self.runcmd("sudo cp %s /root/.pydistutils.cfg" % os.path.expanduser("~/.pydistutils.cfg"))

        self.milestone("Pip configuration updated!")
        return

    def milestone(self, s):
        def green(st):
            prefix = '\x1b[' + '32m'
            suffix = '\x1b[0m'
            return prefix + st + suffix
        self.log.info(green(s))

    def assert_al_in_pythonpath(self):
        al_pkg_root = self.config['system']['root'] + '/pkg'
        if al_pkg_root not in sys.path and not al_pkg_root + '/' in sys.path:
            raise Exception("AL root not found in python path. Have you updated PYTHONPATH in your bashrc ?")

    def fetch_package(self, relpath, localpath='.', realm='assemblyline'):
        self.info("Fetching '{package}' from realm '{realm}'".format(package=relpath, realm=realm))
        self._package_fetcher.fetch(relpath, localpath, realm)

    def check_log_prerequisites(self):
        mach = platform.machine()
        if mach != 'x86_64':
            self.log.warn('Be warned: You are installing on a non stardard machine: %s', mach)
        
        (dist, version, name) = platform.linux_distribution()
        if dist != 'Ubuntu' or version != '14.04':
            self.log.warn('Be warned: You are installing on an unsupported linux distribution: %s',
                          '-'.join([dist, version, name]))

    @staticmethod
    def runcmd(cmdline, shell=True, raise_on_error=True, piped_stdio=True, silent=False, cwd=None):
        return _runcmd(cmdline, shell, raise_on_error, piped_stdio, silent=silent, cwd=cwd)

    def assert_running_in_python_venv(self):
        import sys
        if not hasattr(sys, 'real_prefix'):
            self.log.error("You are not running with the AL virtualenv. Aborting.")
            exit(1)

    def remove_apparmor(self):
        self.milestone('.....Disabling apparmor.')
        if os.path.exists('/lib/apparmor'):
            self.runcmd('sudo service apparmor stop')
            self.runcmd('sudo update-rc.d -f apparmor remove')
            self.runcmd('sudo apt-get -y remove apparmor')

    def pip_install(self, package):
        self.milestone('.....pip installing:' + package)
        self._pipper.install(package)

    def pip_install_all(self, packages):
        for p in packages:
            self.milestone('.....pip installing:' + p)
        self._pipper.install_all(packages)

    def pip_refresh(self):
        self.milestone("Refreshing pip command...")
        self._pipper.resfresh_pip_install_cmd()

    def pip_upgrade(self, package):
        self.milestone('.....pip installing:' + package)
        self._pipper.upgrade(package)

    def pip_upgrade_all(self, packages):
        for p in packages:
            self.milestone('.....pip installing:' + p)
        self._pipper.upgrade_all(packages)

    @staticmethod
    def grep_quiet(filename, content, sudo=True):
        if sudo:
            cmdline = "sudo "
        else:
            cmdline = ""
        cmdline += 'grep -q \"' + content + '\" ' + filename
        rc, _, _ = _runcmd(cmdline, raise_on_error=False)
        return rc == 0

    def append_line_if_doesnt_exist(self, filename, line):
        if not self.grep_quiet(filename, "^" + line):
            self.runcmd('sudo ' + self.shell + ' -c \'echo \"' + line + '\" >> ' + filename + "'")

    @staticmethod
    def get_hostname(silent=False):
        _, hostname, _ = SiteInstaller.runcmd('hostname -A', silent=silent)
        hostname = hostname.strip()

        if not hostname:
            _, hostname, _ = SiteInstaller.runcmd('hostname -f', silent=silent)
            hostname = hostname.strip()

        return hostname

    @staticmethod
    def get_username(silent=False):
        _, uname, _ = SiteInstaller.runcmd('whoami', silent=silent)
        return uname.strip()

    @staticmethod
    def get_ipaddress(silent=False):
        _, ip, _ = SiteInstaller.runcmd('ip route get to 255.255.255.255 | sed -e "s/.*src //" | head -n 1',
                                        silent=silent)
        return ip.strip()

    def sudo_apt_install(self, packages):
        apt_args = ['sudo', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', '-y', '-q', 'install']

        cmd_line = apt_args
        if isinstance(packages, list):
            cmd_line.extend(packages)
            for p in packages:
                self.milestone('.....apt installing:' + p)
        else:
            cmd_line.append(packages)
            self.milestone('.....apt installing:' + packages)
        (_, _, _) = self.runcmd(cmd_line, shell=False)

    def sudo_sed_inline(self, fname, expression_list, check_exist=True, create_backup=True):
        if check_exist and not os.path.isfile(fname):
            raise Exception("No such file to sed_inline: %s", fname)

        cmdline = 'sudo sed -i'
        if create_backup:
            cmdline += ".bak "
        else:
            cmdline += " "
        for expression in expression_list:
            cmdline += " -e '" + expression + "'"
        cmdline += ' ' + fname
        self.milestone('\tUpdating:' + fname)
        self.runcmd(cmdline)

    # if src is a relative path, add the alroot directory as prefix
    def sudo_install_file(self, src, dst, backup=False):
        if not os.path.isabs(src):
            src = os.path.join(self.config['system']['root'], 'pkg', src)
        self.milestone('\tInstalling file:' + dst)
        self._install_file(src, dst, backup, sudo=True)

    def install_file(self, src, dst, backup=False):
        if not os.path.isabs(src):
            src = os.path.join(self.config['system']['root'], 'pkg', src)
        self.milestone('\tInstalling file:' + dst)
        self._install_file(src, dst, backup, sudo=False)

    def execute_core_preinstall_hook(self):
        hook_paths = self.config['installation']['hooks'].get('core_pre', [])
        if not hook_paths:
            return

        if isinstance(hook_paths, str):
            raise Exception("install_hooks must be a list")

        for hook_path in hook_paths:
            import importlib
            hook_module = importlib.import_module(hook_path)
            if not hasattr(hook_module, 'execute'):
                self.warn("Specified hook as no execute method. Aborting hook: %s\n%s" %
                          (hook_path, str(dir(hook_module))))
                return

            # grab the hook call it
            hook_cb = getattr(hook_module, 'execute')
            hook_cb(self)

    def execute_ui_preinstall_hook(self):
        hook_paths = self.config['installation']['hooks'].get('ui_pre', [])
        if not hook_paths:
            return

        if isinstance(hook_paths, str):
            raise Exception("install_hooks must be a list")

        import importlib
        for hook_path in hook_paths:
            hook_module = importlib.import_module(hook_path)
            if not hasattr(hook_module, 'execute'):
                self.warn("Specified hook as no execute method. Aborting hook: %s\n" % hook_path)
                return

            # grab the hook method and call it
            hook_cb = getattr(hook_module, 'execute')
            hook_cb(self)

    def execute_riak_preinstall_hook(self):
        hook_paths = self.config['installation']['hooks'].get('riak_pre', [])
        if not hook_paths:
            return

        if isinstance(hook_paths, str):
            raise Exception("install_hooks must be a list")

        for hook_path in hook_paths:
            import importlib
            hook_module = importlib.import_module(hook_path)
            if not hasattr(hook_module, 'execute'):
                self.warn("Specified hook as no execute method. Aborting hook: %s\n%s" % hook_path)
                return

            # grab the hook call it
            hook_cb = getattr(hook_module, 'execute')
            hook_cb(self)

    def _install_file(self, src, dst, backup, sudo):
        cmdprefix = 'install -D '
        if backup:
            suffix = time.strftime('%FT%T')
            cmdprefix = 'install -bDS .{suffix} '.format(suffix=suffix)

        cmdline = '{cmdprefix} {local} {dst}'.format(cmdprefix=cmdprefix, local=src, dst=dst)
        if sudo:
            # noinspection PyAugmentAssignment
            cmdline = 'sudo ' + cmdline
        self.runcmd(cmdline)

    def install_yara_3(self):
        # Check if yara-python version already installed
        try:
            cmd_output = self.runcmd('pip show yara-python')[1]
        except:
            cmd_output = ''
        if "Version: 3.6.3" not in cmd_output:
            wd = os.getcwd()
            local_yara_support = os.path.join(self.alroot, 'support/yara/')
            local_yara_python = os.path.join(local_yara_support, 'yara-python-3.6.3.tar.gz')
            self.fetch_package('yara/yara-python-3.6.3.tar.gz', local_yara_python)

            os.chdir(local_yara_support)
            self.runcmd("tar -zxf yara-python-3.6.3.tar.gz")
            os.chdir(os.path.join(local_yara_support, "yara-python-3.6.3"))
            self.runcmd("python setup.py build --enable-dotnet")
            self.runcmd("sudo python setup.py install")
            os.chdir(wd)

    def install_oracle_java8(self):
        self.milestone("Installing Oracle Java 8...")
        self.sudo_apt_install([
            'java-common',
        ])
        _, _, stderr = self.runcmd("java -version", raise_on_error=False)
        if "1.8.0_72" not in stderr:
            jdk = "jdk-8u72-linux-x64.tar.gz"
            installer = "oracle-java8-installer_8u72+8u71arm-1-webupd8-0_all.deb"
            defaults = "oracle-java8-set-default_8u72+8u71arm-1-webupd8-0_all.deb"

            jdk_remote = "oracle/%s" % jdk
            installer_remote = "oracle/%s" % installer
            defaults_remote = "oracle/%s" % defaults

            local_jdk = os.path.join('/tmp/jdk_installer/', jdk)
            local_installer = os.path.join('/tmp/jdk_installer/', installer)
            local_defaults = os.path.join('/tmp/jdk_installer/', defaults)

            self.fetch_package(jdk_remote, local_jdk)
            self.fetch_package(installer_remote, local_installer)
            self.fetch_package(defaults_remote, local_defaults)

            self.runcmd("sudo mkdir /var/cache/oracle-jdk8-installer/")
            self.runcmd("sudo ln -s %s /var/cache/oracle-jdk8-installer/jdk-8u72-linux-x64.tar.gz" % local_jdk)
            self.runcmd("echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | "
                        "sudo /usr/bin/debconf-set-selections")
            self.runcmd("sudo dpkg -i %s" % local_installer)
            self.runcmd("sudo dpkg -i %s" % local_defaults)
        else:
            self.info("Oracle Java 8 already installed. Skipping...")
        self.milestone("Oracle Java 8 installation completed!")

    def install_docker(self):
        self.milestone("Installing Docker...")
        self.sudo_apt_install("software-properties-common")
        self.runcmd('sudo add-apt-repository "%s"' % self.config['installation']['docker']['apt_repo_info'])
        self.runcmd("wget -q %s -O- | sudo apt-key add -" % self.config['installation']['docker']['apt_repo_key_url'])
        self.runcmd("sudo apt-get update -m", raise_on_error=False)
        self.sudo_apt_install(['docker-engine'])
        self.pip_install('docker-py')
        self.runcmd("sudo gpasswd -a %s docker" % self.get_username())
        self.runcmd("sudo gpasswd -a %s docker" % self.config['system']['user'])
        if 'private_registry' in self.config['installation']['docker']:
            if 'private_registry_key' in self.config['installation']['docker']:
                self.runcmd("sudo mkdir /usr/local/share/ca-certificates/docker-dev-cert", raise_on_error=False)
                self.runcmd('echo "%s" | sudo tee /usr/local/share/ca-certificates/docker-dev-cert/devdockerCA.crt' %
                            self.config['installation']['docker']['private_registry_key'])
                self.runcmd("sudo mkdir -p /etc/docker/certs.d/%s/" %
                            self.config['installation']['docker']['private_registry'], raise_on_error=False)
                self.runcmd('sudo cp /usr/local/share/ca-certificates/docker-dev-cert/devdockerCA.crt '
                            '/etc/docker/certs.d/%s/ca.crt' % self.config['installation']['docker']['private_registry'])
                self.runcmd("sudo update-ca-certificates")

            else:
                self.runcmd('echo \'DOCKER_OPTS="--insecure-registry %s"\' | sudo tee -a /etc/default/docker' %
                            self.config['installation']['docker']['private_registry'])

            if 'private_registry_auth' in self.config['installation']['docker']:
                docker_cfg_dir = os.path.join(self.config['system']['root'], '.docker/')
                docker_cfg_path = os.path.join(docker_cfg_dir, 'config.json')
                docker_cfg_temp = "/tmp/docker_cfg"
                registry_uri = "https://%s" % self.config['installation']['docker']['private_registry']
                if not os.path.exists(docker_cfg_dir):
                    self.runcmd("sudo mkdir %s" % docker_cfg_dir)

                if os.path.exists(docker_cfg_path):
                    with open(docker_cfg_path, 'r') as fh:
                        docker_cfg = json.load(fh)
                else:
                    docker_cfg = {}

                if 'auths' not in docker_cfg:
                    docker_cfg["auths"] = {}
                docker_cfg["auths"][registry_uri] = {
                    "auth": self.config['installation']['docker']['private_registry_auth'],
                    "email": "",
                }
                # Just to avoid echo destroying our string..
                with open('/tmp/docker_cfg', 'w') as fh:
                    json.dump(docker_cfg, fh, indent=4)
                self.runcmd('sudo mv %s %s' % (docker_cfg_temp, docker_cfg_path))

        self.runcmd("sudo service docker restart")
        self.milestone("Docker installation completed!")

    def symlink(self, src, dst):
        if not os.path.isabs(src):
            src = os.path.join(self.alroot, 'pkg', src)
        if not os.path.isabs(dst):
            dst = os.path.join(self.alroot, 'pkg', dst)

        if os.path.exists(dst):
            # already links
            return

        self.info("Linking %s --> %s", src, dst)
        try:
            os.symlink(src, dst)
        except OSError, os_err:
            if os_err.errno == 17:
                pass
            else:
                raise

    def install_pefile(self):
        # pefile 1.2.10-114 is not provided by pypi anymore therefor the following won't work
        # self.pip_install('pefile==1.2.10-114')
        # until we've tested newer versions of pefile, we will install it from an sdist package
        pefile_pkg = 'pefile-1.2.10-114.tar.gz'
        remote_path = 'python/pip/' + pefile_pkg
        local_path = os.path.join('/tmp/', pefile_pkg)
        self.fetch_package(remote_path, local_path)
        self.runcmd('sudo -H pip install ' + local_path, piped_stdio=False)


def _runcmd(cmdline, shell=True, raise_on_error=True, piped_stdio=True, silent=False, cwd=None):
    if not silent:
        if not cwd:
            print "Running: %s" % cmdline
        else:
            print "Running: %s (%s)" % (cmdline, cwd)

    if piped_stdio:
        p = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell, cwd=cwd)
    else:
        p = subprocess.Popen(cmdline, shell=shell, cwd=cwd)

    stdout, stderr = p.communicate()
    rc = p.returncode
    if raise_on_error and rc != 0:
        raise Exception("FAILED: return_code:%s\nstdout:\n%s\nstderr:\n%s" % (rc, stdout, stderr))
    return rc, stdout, stderr


def assert_windows2008_r2():
    expected = '2008ServerR2'
    found = platform.win32_ver()[0]
    if found == expected:
        return
    raise Exception('Platform Assertion Failure. Found: %s vs %s' % (found, expected))


class PipInstaller(object):

    def __init__(self, pypi_index_url=None):
        self.indexurl = pypi_index_url
        self.pip = 'pip'
        self.pip_install_cmd = self._get_pip_install_cmd()

    def _get_pip_install_cmd(self):
        if 'linux' in platform.system().lower():
            pip_install_cmd = ['sudo', '-H', self.pip, 'install']
        else:
            pip_install_cmd = [self.pip, 'install']

        if self.indexurl:
            pip_install_cmd.append('--index-url=' + self.indexurl)
            if self.require_trusted_host():
                host = urlparse(self.indexurl).hostname
                pip_install_cmd.append('--trusted-host=' + host)

        return pip_install_cmd

    def install(self, package):
        assert(isinstance(package, str))
        _, out, _ = _runcmd(self.pip_install_cmd + [package], shell=False)

    def install_all(self, packages):
        assert(isinstance(packages, list))
        _, out, _ = _runcmd(self.pip_install_cmd + packages, shell=False)

    # noinspection PyUnresolvedReferences
    def require_trusted_host(self):
        try:
            rc, out, _ = _runcmd([self.pip, '-V'], raise_on_error=False, shell=False, silent=True)
            if rc == 0:
                pip_ver = out.split(" from")[0].replace("pip ", "")
                return int(pip_ver[0]) >= 8
            else:
                return False
        except OSError:
            return False

    def resfresh_pip_install_cmd(self):
        self.pip_install_cmd = self._get_pip_install_cmd()

    def upgrade(self, package):
        assert(isinstance(package, str))
        _, out, _ = _runcmd(self.pip_install_cmd + ['--upgrade', package], shell=False)

    def upgrade_all(self, packages):
        assert(isinstance(packages, list))
        _, out, _ = _runcmd(self.pip_install_cmd + ['--upgrade'] + packages, shell=False)
