#!/usr/bin/env python

import os
import subprocess
import logging

from assemblyline.common.net import get_hostname, get_hostip
from assemblyline.al.common import log as al_log, queue
from assemblyline.al.common import message

al_log.init_logging('harddrive_monitor')
log = logging.getLogger('assemblyline.harddrive_monitor')


def is_drive_ok(smart_output):
    for line in smart_output.splitlines():
        if "SMART Health Status" in line:
            status = line.split("SMART Health Status:")[1].strip()
            if status == "OK":
                return True
            else:
                return False
        elif "SMART overall-health self-assessment test result" in line:
            status = line.split("SMART overall-health self-assessment test result:")[1].strip()
            if status == "PASSED":
                return True
            else:
                return False
    return False


def start():
    bad_disks = []
    # Test if smartmontools is installed
    try:
        subprocess.call(['smartctl'], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError:
        # Install smartmontools
        ret = subprocess.call(["sudo", "apt-get", "-y", "install", "smartmontools"],
                              stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if ret != 0:
            exit("Can't install smartmontools, stopping...")

    # Find drives
    proc = subprocess.Popen(['smartctl', '--scan'], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = proc.communicate()

    if out:
        device = out.split(" ")[0]

        for x in xrange(16):
            status_proc = subprocess.Popen(['smartctl', '-H', '-d', 'megaraid,%s' % x, device],
                                           stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            status_out, status_err = status_proc.communicate()
            if "INQUIRY failed" in status_out:
                break
            else:
                # Report status
                if is_drive_ok(status_out):
                    log.info("All is good with drive: %s [disk: %s]" % (device, x))
                else:
                    bad_disks.append((device, x))
                    log.error("Device %s [disk: %s] has a failure state. Report to your administrator." % (device, x))

        if len(bad_disks) > 0:
            bad_disk_body = {
                'hostname': get_hostname(),
                'ip': get_hostip(),
                'bad_disks': [x[1] for x in bad_disks],
                'device': device
            }
            msg = message.Message(to="*", sender='harddrive_monitor',
                                  mtype=message.MT_HARDDRIVE_FAILURES,
                                  body=bad_disk_body).as_dict()
            statusq = queue.CommsQueue('status')
            statusq.publish(msg)


if __name__ == "__main__":
    if os.geteuid() != 0:
        exit("This script needs to run as root, stopping...")

    start()
