#!/usr/bin/env python

import os
import sys

from assemblyline.al.common.backupmanager import BackupWorker

if __name__ == "__main__":
    # This will create a backup worker based of the parameters passed by arguments

    # noinspection PyBroadException
    try:
        arg_worker_type = int(sys.argv[1])
        arg_wid = int(sys.argv[2])
        arg_working_dir = " ".join(sys.argv[3:])
        arg_instance_id = sys.argv[4]
    except:
        print >> sys.stderr, "Failed to initialised backup worker. You need to provide a worker type, " \
                             "a worker ID and a working directory."
        sys.exit(1)

    if not os.path.exists(arg_working_dir):
        os.makedirs(arg_working_dir)

    backup_worker = BackupWorker(arg_wid, arg_worker_type, arg_working_dir, arg_instance_id)
    backup_worker.run()

