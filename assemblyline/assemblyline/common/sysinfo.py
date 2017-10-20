
import platform
import subprocess

from assemblyline.common import net


def get_osinfo():
    os_type = platform.system()
    vers = platform.version()
    arch = platform.machine()
    
    if os_type == "Linux":
        if "buntu" in vers:
            version_cmd = subprocess.Popen(['lsb_release', '-a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = "\n".join(version_cmd.communicate())
    
            for line in output.splitlines():
                if 'Description:' in line:
                    vers = line.split('Description:')[1].strip()
    
    return "%s (%s - %s)" % (os_type, vers, arch)

   
def get_platform():
    return dict(zip(['system', 'node', 'release', 'version', 'machine', 'proc'], platform.uname()))


def get_machine_info(is_agent=False):
    import psutil
    out = {'cores': len(psutil.cpu_percent(interval=0.01, percpu=True)),
           'memory': "%.1f" % (float(psutil.phymem_usage().total) / 1024 / 1024 / 1024), 'os': get_osinfo(),
           'ip': net.get_hostip()}
    if is_agent:
        out['uid'] = "Agent-" + net.get_mac_address()
    else:
        out['uid'] = "Core-" + net.get_mac_address()
    out['name'] = net.get_hostname()
    
    return out
