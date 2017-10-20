import shlex
import json
import subprocess
import uuid
import logging
from os import path

from assemblyline.al.common import forge


class DockerException(Exception):
    pass


class DockerManager(object):
    def __init__(self, stub_name, log_name):
        config = forge.get_config()
        self.registry_host = config.installation.docker.get('private_registry', None)
        self.log = logging.getLogger(log_name)
        self.docker_count = 0
        self.docker_contexts = {}
        self.project_id = str(uuid.uuid4()).replace("-", "")
        self.stub_name = "%s_%s_%%i" % (self.project_id, stub_name)

    def add_container(self, ctx, name=None):
        """Add a container template to the list of contexts, returns the template name.

        ctx schema:
            {
                "image": <image name>[:tag],
                "commandline": [container argument list],
                "detatch": True/False,
                "privileged": True/False,
                "volumes: [list of (source, dest, access) tuples],
                "caps": [list of container capabilities],
                "user": Username or UID: (format: <name|uid>[:<group|gid>])
                "ram": max memory usage
            }
        All keys default as empty or False if not included. Image is the only mandatory field.
        """
        if name is None:
            name = self.stub_name % self.docker_count

        self.docker_count += 1
        ctx['name'] = name
        ctx['started'] = False
        self.docker_contexts[name] = ctx
        return name

    def remove_container(self, name=None):
        """Remove one or more containers. If name is None, all containers are removed.
        If a container is started, it will be stopped."""
        if name is None:
            names = self.docker_contexts.keys()
        elif isinstance(name, str):
            names = [name]
        elif isinstance(name, list):
            names = name
        else:
            raise ValueError("Unknown name type %s" % type(name))
        for container_name in names:
            if self.docker_contexts[container_name]['started']:
                self.stop(container_name)
            del self.docker_contexts[container_name]

    def start_container(self, name, stdin=None):
        """Start a container by name, name cannot be None. If detact is set to False this function will only return
        when the container stops. If a container is set to detactch then return the IP, else return stdout, stderr.
        If detatch is False and stdin is not None, stdin is passed to the docker container."""

        ctx = self.docker_contexts[name]
        if self.registry_host:
            image_name = path.join(self.registry_host, ctx['image'])
        else:
            image_name = ctx['image']

        # Pull the image
        self._run_cmd("docker pull %s" % image_name, raise_on_error=False)

        # Run the image
        run_args = ["--rm=true", "--name=%s" % name]
        detatch = False
        if ctx.get("detatch", False):
            detatch = True
            run_args.append("-d")
        if ctx.get("privileged", False):
            run_args.append("--privileged")
        for cap in ctx.get("caps", []):
            run_args.append("--cap-add=%s" % cap)
        if "ram" in ctx:
            run_args.append("--memory %s" % ctx["ram"])
        if "user" in ctx:
            run_args.append("--user %s" % ctx["user"])
        for volume in ctx.get("volumes", []):
            run_args.append("--volume %s:%s:%s" % volume)
        run_args.append(image_name)
        for command in ctx.get("commandline", []):
            run_args.append(command)

        run_str = "docker run %s" % " ".join(run_args)

        stdout, stderr = self._run_cmd(run_str, raise_on_error=False, stdin=stdin, log=self.log)
        if detatch:
            ctx['started'] = True
            for line in stderr.splitlines():
                line = line.strip()
                if len(line) > 0:
                    self.log.info(line)
            ctx['info'] = self.inspect(ctx['name'])
            ctx['ip'] = ctx['info']['NetworkSettings']['IPAddress']
            return ctx['ip']
        else:
            return stdout, stderr

    @staticmethod
    def _run_cmd(command, raise_on_error=True, log=None, stdin=None):
        arg_list = shlex.split(command)
        kwargs = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}
        if stdin is not None:
            kwargs['stdin'] = subprocess.PIPE
        proc = subprocess.Popen(arg_list, **kwargs)
        stdout, stderr = proc.communicate(input=stdin)
        if stderr and raise_on_error:
            if log is not None:
                log.error("Command has returned an error: %s STDERR: '%s'" % (command, stderr))
            raise DockerException(stderr)
        return stdout, stderr

    def inspect(self, container_name):
        inspect_cmd = "docker inspect %s" % container_name
        stdout, stderr = self._run_cmd(inspect_cmd)
        # noinspection PyBroadException
        try:
            info = json.loads(stdout)
        except:
            raise DockerException("Unable to query container information, this is likely fatal.")
        return info[0]

    def stop(self, name=None):
        """Shutdown one or more containers. If name is None, all containers are shutdown."""
        if name is None:
            for container_name in self.docker_contexts.keys():
                self._run_cmd("docker rm --force %s" % container_name)
        else:
            self._run_cmd("docker rm --force %s" % name)

