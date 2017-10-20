#!/usr/bin/env python
# coding=utf-8

# Suppress all warnings
import warnings
warnings.filterwarnings("ignore")

import cmd
import inspect
import sys
import multiprocessing
import os
import re
import signal
import time
import uuid
import shutil

from pprint import pprint

from assemblyline.common.importing import module_attribute_by_name
from assemblyline.common.net import get_mac_address
from assemblyline.al.common import forge, log as al_log
from assemblyline.al.common.backupmanager import DistributedBackup
from assemblyline.al.common.message import send_rpc
from assemblyline.al.common.queue import reply_queue_name, NamedQueue
from assemblyline.al.common.remote_datatypes import Hash
from assemblyline.al.common.security import get_totp_token, generate_async_keys
from assemblyline.al.common.task import Task
from assemblyline.al.core.agents import AgentRequest, ServiceAgentClient, VmmAgentClient
from assemblyline.al.core.controller import ControllerClient
from assemblyline.al.core.dispatch import DispatchClient
from assemblyline.al.service import register_service

config = forge.get_config()
config.logging.log_to_console = False
al_log.init_logging('cli')

RESET_COLOUR = '\033[0m'
YELLOW_COLOUR = '\033[93m'
PROCESSES_COUNT = 50
COUNT_INCREMENT = 500
DATASTORE = None
t_count = 0
t_last = time.time()
YaraParser = forge.get_yara_parser()


def init():
    global DATASTORE
    DATASTORE = forge.get_datastore()
    signal.signal(signal.SIGINT, signal.SIG_IGN)


# noinspection PyProtectedMember
def bucket_delete(bucket_name, key):
    try:
        DATASTORE._delete_bucket_item(DATASTORE.get_bucket(bucket_name), key)
    except Exception, e:
        print e
        return "DELETE", bucket_name, key, False

    return "deleted", bucket_name, key, True


# noinspection PyProtectedMember
def update_signature_status(status, key, datastore=None):
    try:
        global DATASTORE
        if not DATASTORE:
            DATASTORE = datastore
        data = DATASTORE._get_bucket_item(DATASTORE.get_bucket('signature'), key)
        data['meta']['al_status'] = status
        data = DATASTORE.sanitize('signature', data, key)
        DATASTORE._save_bucket_item(DATASTORE.get_bucket('signature'), key, data)
    except Exception, e:
        print e


def submission_delete_tree(key):
    try:
        with forge.get_filestore() as f_transport:
            DATASTORE.delete_submission_tree(key, transport=f_transport)
    except Exception, e:
        print e
        return "DELETE", "submission", key, False

    return "deleted", "submission", key, True


def action_done(args):
    global t_count, t_last, COUNT_INCREMENT
    action, bucket, key, success = args
    if success:
        t_count += 1
        if t_count % COUNT_INCREMENT == 0:
            new_t = time.time()
            print "[%s] %s %s so far (%s at %s keys/sec)" % \
                  (bucket, t_count, action, new_t - t_last, int(COUNT_INCREMENT / (new_t - t_last)))
            t_last = new_t
    else:
        print "!!ERROR!! [%s] %s ==> %s" % (bucket, action, key)


def _reindex_template(bucket_name, keys_function, get_function, save_function, bucket=None, filter_out=None):
        if not filter_out:
            filter_out = []

        print "\n%s:" % bucket_name.upper()
        print "\t[x] Listing keys..."
        keys = keys_function()

        print "\t[-] Re-indexing..."
        for key in keys:
            skip = False
            for f in filter_out:
                if f in key:
                    skip = True
            if skip:
                continue
            if bucket:
                value = get_function(bucket, key)
                save_function(bucket, key, value)
            else:
                value = get_function(key)
                save_function(key, value)

        print "\t[x] Indexed!"


# noinspection PyMethodMayBeStatic,PyProtectedMember,PyBroadException
class ALCommandLineInterface(cmd.Cmd):  # pylint:disable=R0904

    def __init__(self, show_prompt=True):
        cmd.Cmd.__init__(self)
        self.local_mac = get_mac_address()
        self.mac = self.local_mac  # the mac we are currently targetting.
        self.queue = None
        self.prompt = ""
        self.intro = ""
        self.datastore = forge.get_datastore()
        self.controller_client = ControllerClient(async=False)
        self.vmm_client = VmmAgentClient(async=False)
        self.svc_client = ServiceAgentClient(async=False)
        self.config = forge.get_config()
        if show_prompt:
            self._update_context()

        self.wipe_map = {
            'result': self.datastore.wipe_results,
            'alert': self.datastore.wipe_alerts,
            'submission': self.datastore.wipe_submissions,
            'error': self.datastore.wipe_errors,
            'file': self.datastore.wipe_files,
            'user': self.datastore.wipe_users,
            'signature': self.datastore.wipe_signatures,
            'profile': self.datastore.wipe_profiles,
            'emptyresult': self.datastore.wipe_emptyresults,
            'filescore': self.datastore.wipe_filescores,
            'vm': self.datastore.wipe_vm_nodes,
            'node': self.datastore.wipe_nodes,
            'blob': self.datastore.wipe_blobs,
            'workflow': self.datastore.wipe_workflows
        }

    def _update_context(self):
        label = 'local' if self.mac == self.local_mac else 'remote'
        self.prompt = '%s (%s)> ' % (self.mac, label)
        self.queue = NamedQueue(self.mac)
        self.intro = 'AL 3.1 - Console. (type help).'

    def _send_agent_cmd(self, command, args=None):
        self.queue.push(AgentRequest(self.mac, command, body=args))

    def _send_agent_rpc(self, command, args=None):
        return send_rpc(AgentRequest(self.mac, command, body=args))

    def _parse_args(self, s, platform='this'):
        """Multi-platform variant of shlex.split() for command-line splitting.
        For use with subprocess, for argv injection etc. Using fast REGEX.

        platform: 'this' = auto from current platform;
                  1 = POSIX;
                  0 = Windows/CMD
                  (other values reserved)
        """
        if platform == 'this':
            platform = (sys.platform != 'win32')
        if platform == 1:
            cmd_lex = r'''"((?:\\["\\]|[^"])*)"|'([^']*)'|(\\.)|(&&?|\|\|?|\d?\>|[<])|([^\s'"\\&|<>]+)|(\s+)|(.)'''
        elif platform == 0:
            cmd_lex = r'''"((?:""|\\["\\]|[^"])*)"?()|(\\\\(?=\\*")|\\")|(&&?|\|\|?|\d?>|[<])|([^\s"&|<>]+)|(\s+)|(.)'''
        else:
            raise AssertionError('unkown platform %r' % platform)

        args = []
        accu = None  # collects pieces of one arg
        for qs, qss, esc, pipe, word, white, fail in re.findall(cmd_lex, s):
            if word:
                pass  # most frequent
            elif esc:
                word = esc[1]
            elif white or pipe:
                if accu is not None:
                    args.append(accu)
                if pipe:
                    args.append(pipe)
                accu = None
                continue
            elif fail:
                raise ValueError("invalid or incomplete shell string")
            elif qs:
                word = qs.replace('\\"', '"').replace('\\\\', '\\')
                if platform == 0:
                    word = word.replace('""', '"')
            else:
                word = qss  # may be even empty; must be last

            accu = (accu or '') + word

        if accu is not None:
            args.append(accu)

        return args

    def _print_error(self, msg):
        stack_func = None
        stack = inspect.stack()
        for item in stack:
            if 'cli.py' in item[1] and '_print_error' not in item[3]:
                stack_func = item[3]
                break

        if msg:
            print "ERROR: " + msg + "\n"

        if stack_func:
            function_doc = inspect.getdoc(getattr(self, stack_func))
            if function_doc:
                print "Function help:\n\n" + function_doc + "\n"

    #
    # Exit actions
    #
    def do_exit(self, arg):
        """Quits the CLI"""
        arg = arg or 0
        sys.exit(int(arg))

    def do_quit(self, arg):
        """Quits the CLI"""
        self.do_exit(arg)

    #
    # Backup actions
    #
    def do_backup(self, args):
        """
        Backup the database content to a set of json files

        Usage:
            backup <destination_folder>
                   <destination_folder> <bucket_name> [follow] [force] <query>

        Parameters:
            <destination_folder> Path to the destination folder [required]

            <bucket_name>        Name of the bucket to backup [required in backup by query]

            follow               Follow IDs to backup more then the specified bucket
                                 [optional, only used in backup by query]

            force                Automatically perform backup without asking for confirmation
                                 [optional, only used in backup by query]

            <query>              Query that the data need to match
                                 [optional, only used in backup by query]

        Examples:
            # Create a backup of the system buckets
            backup /tmp/backup_folder

            # Created a backup of all alerts
            backup /tmp/alerts_backup alert "*:*"
        """
        args = self._parse_args(args)

        follow = False
        if 'follow' in args:
            follow = True
            args.remove('follow')

        force = False
        if 'force' in args:
            force = True
            args.remove('force')

        if len(args) == 1:
            dest = args[0]
            system_backup = True
            bucket = None
            follow = False
            query = None
        elif len(args) == 3:
            dest, bucket, query = args
            system_backup = False
        else:
            self._print_error("Wrong number of arguments for backup command.")
            return

        if system_backup:
            backup_manager = DistributedBackup(dest, worker_count=5)
            backup_manager.backup(["blob", "node", "profile", "signature", "user"])
        else:
            data = self.datastore._search_bucket(self.datastore.get_bucket(bucket), query, start=0, rows=1)
            total = data['total']
            if not total:
                print "\nNothing in '%s' matches the query:\n\n  %s\n" % (bucket.upper(), query)
                return
            else:
                print "\nNumber of items matching this query: %s\n" % data["total"]

            if not force:
                print "This is an exemple of the data that will be backuped:\n"
                print data['items'][0], "\n"
                if self.prompt:
                    cont = raw_input("Are your sure you want to continue? (y/N) ")
                    cont = cont == "y"
                else:
                    print "You are not in interactive mode therefor the backup was not executed. " \
                          "Add 'force' to your commandline to execute the backup."
                    cont = False

                if not cont:
                    print "\n**ABORTED**\n"
                    return

            if follow:
                total *= 100

            try:
                if not os.path.exists(dest):
                    os.makedirs(dest)
            except:
                print "Cannot make %s folder. Make sure you can write to this folder. " \
                      "Maybe you should write your backups in /tmp ?" % dest
                return

            backup_manager = DistributedBackup(dest, worker_count=max(1, min(total / 1000, 50)))

            try:
                backup_manager.backup([bucket], follow_keys=follow, query=query)
            except KeyboardInterrupt:
                backup_manager.terminate()
                raise

    def do_restore(self, args):
        """
        Restore a backup created by the backup command

        Usage:
            restore <backup_directory>

        Parameters:
            <backup_directory> Path to the backup folder [required]

        Examples:
            restore /tmp/backup_folder
        """
        args = self._parse_args(args)

        if len(args) not in [1]:
            self._print_error("Wrong number of arguments for restore command.")
            return

        path = args[0]
        if not path:
            self._print_error("You must specify an input folder.")
            return

        workers = len([x for x in os.listdir(path) if '.part' in x])

        backup_manager = DistributedBackup(path, worker_count=workers)

        try:
            backup_manager.restore()
        except KeyboardInterrupt:
            backup_manager.terminate()
            raise

    #
    # Seed actions
    #
    def do_reseed(self, args):
        """
        Change your current seed from a code based seed or a previous backup

        Usage:
            reseed current
                   previous
                   module <python_path_of_seed> [<destination_blob>]

        Parameters:
            current   reload the current seed from it's code version
            previous  reload the previous iteration of your seed
            module    load a code seed file into the system
            <python_path_of_seed>  python package path to the seed file
            [<destination_blob>]   destination where the module will be loaded
                                   [default: seed]

        Examples:
            # reload your deployment seed
            reseed module al_private.seeds.deployment.seed
        """
        args = self._parse_args(args)

        if len(args) not in [1, 2, 3]:
            self._print_error("Wrong number of arguments for reseed command.")
            return

        action_type = args[0]

        if action_type == 'current':
            seed_path = self.datastore.get_blob('seed_module')
            target = 'seed'
        elif action_type == 'previous':
            cur_seed = self.datastore.get_blob('seed')
            self.datastore.save_blob('seed', self.datastore.get_blob('previous_seed'))
            self.datastore.save_blob('previous_seed', cur_seed)
            print "Current and previous seed where swapped."
            return
        elif action_type == 'module':
            if len(args) == 2:
                seed_path = args[1]
                target = 'seed'
            elif len(args) == 3:
                seed_path, target = args[1:]
            else:
                self._print_error("Wrong number of arguments for reseed command.")
                return
        else:
            self._print_error("Invalid reseed action '%s' must be one of current, previous or module.")
            return

        try:
            seed = module_attribute_by_name(seed_path)
        except:
            print "Unable to load seed form path: %s" % seed_path
            return

        services_to_register = seed['services']['master_list']

        for service, svc_detail in services_to_register.iteritems():
            classpath = svc_detail.get('classpath', "al_services.%s.%s" % (svc_detail['repo'],
                                                                           svc_detail['class_name']))
            config_overrides = svc_detail.get('config', {})

            new_srv_registration = register_service.register(classpath, config_overrides=config_overrides,
                                                             store_config=False,
                                                             enabled=svc_detail.get('enabled', True))
            seed['services']['master_list'][service].update(new_srv_registration)

        if target == "seed":
            cur_seed = self.datastore.get_blob('seed')
            self.datastore.save_blob('previous_seed', cur_seed)
            print "Current seed was copied to previous_seed key."

        self.datastore.save_blob(target, seed)
        print "Module '%s' was loaded into blob '%s'." % (seed_path, target)

    #
    # Delete actions
    #
    def do_delete(self, args):
        """
        Delete all data from a bucket that match a given query

        Usage:
            delete <bucket> [full] [force] <query>

        Parameters:
            <bucket>  Name of the bucket to delete from
            full      Follow IDs and remap classification
                      [Optional: Only work while deleting submissions]
            force     Automatically perform deletion without asking for confirmation [optional]
            <query>   Query to run to find the data to delete

        Examples:
            # Delete all submission for "user" with all associated results
            delete submission full "submission.submitter:user"
        """
        valid_buckets = self.datastore.INDEXED_BUCKET_LIST + self.datastore.ADMIN_INDEXED_BUCKET_LIST
        args = self._parse_args(args)

        if 'full' in args:
            full = True
            args.remove('full')
        else:
            full = False

        if 'force' in args:
            force = True
            args.remove('force')
        else:
            force = False

        if len(args) != 2:
            self._print_error("Wrong number of arguments for delete command.")
            return

        bucket, query = args

        if bucket not in valid_buckets:
            self._print_error("\nInvalid bucket specified: %s\n\n"
                              "Valid buckets are:\n%s" % (bucket, "\n".join(valid_buckets)))
            return

        pool = multiprocessing.Pool(processes=PROCESSES_COUNT, initializer=init)
        try:
            cont = force
            test_data = self.datastore._search_bucket(self.datastore.get_bucket(bucket), query, start=0, rows=1)
            if not test_data["total"]:
                print "Nothing matches the query."
                return

            if not force:
                print "\nNumber of items matching this query: %s\n\n" % test_data["total"]
                print "This is an example of the data that will be deleted:\n"
                print test_data['items'][0], "\n"
                if self.prompt:
                    cont = raw_input("Are your sure you want to continue? (y/N) ")
                    cont = cont == "y"

                    if not cont:
                        print "\n**ABORTED**\n"
                        return
                else:
                    print "You are not in interactive mode therefor the delete was not executed. " \
                          "Add 'force' to your commandline to execute the delete."
                    return

            if cont:
                for data in self.datastore.stream_search(bucket, query, fl="_yz_rk", item_buffer_size=COUNT_INCREMENT):
                    if full and bucket == 'submission':
                        func = submission_delete_tree
                        func_args = (data["_yz_rk"],)
                    else:
                        func = bucket_delete
                        func_args = (bucket, data["_yz_rk"])

                    pool.apply_async(func, func_args, callback=action_done)

        except KeyboardInterrupt, e:
            print "Interrupting jobs..."
            pool.terminate()
            pool.join()
            raise e
        except Exception, e:
            print "Something when wrong, retry!\n\n %s\n" % e
        else:
            pool.close()
            pool.join()
            self.datastore.commit_index(bucket)
            print "Data of bucket '%s' matching query '%s' has been deleted." % (bucket, query)

    #
    # Bucket actions
    #
    def do_node(self, args):
        """
        Perform operation on a worker node

        Usage:
            node list
                 disable  <id>
                 enable   <id>
                 hearbeat <id>
                 remove   <id>
                 restart  <id>
                 show     <id>
                 stop     <id>
                 start    <id>
                 status   <id>

        Actions:
            list      List all nodes on the system
            disable   Disable the node
            enable    Enable the node
            hearbeat  Show the next heartbeat from the node (CPU, RAM and disk usage)
            remove    Remove the node from the system
            restart   Restart processing on the node
            show      Show the node description
            stop      Stop processing on the node
            start     Start processing on the node
            status    Get the status of processing on the node

        Parameters:
            <id>   ID of the worker node, mac address, to perform the action on

        Examples:
            # Restart processing on the node
            node restart 52540027629C
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove', 'start',
                         'stop', 'restart', 'status', 'heartbeat']
        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            item_id = None
        elif len(args) == 2:
            action_type, item_id = args
        else:
            self._print_error("Wrong number of arguments for node command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for node command.")
            return

        if action_type == 'list':
            for key in self.datastore.list_node_keys():
                print key
        elif action_type == 'show' and item_id:
            pprint(self.datastore.get_node(item_id))
        elif action_type == 'disable' and item_id:
            item = self.datastore.get_node(item_id)
            if item:
                item['enabled'] = False
                self.datastore.save_node(item_id, item)
                print "%s was disabled" % item_id
            else:
                print "%s does not exist" % item_id
        elif action_type == 'enable' and item_id:
            item = self.datastore.get_node(item_id)
            if item:
                item['enabled'] = True
                self.datastore.save_node(item_id, item)
                print "%s was enabled" % item_id
            else:
                print "%s does not exist" % item_id
        elif action_type == 'remove' and item_id:
            self.datastore.delete_node(item_id)
            print "Node %s removed." % item_id
        elif action_type == 'start' and item_id:
            pprint(self.controller_client.start(item_id))
        elif action_type == 'stop' and item_id:
            pprint(self.controller_client.stop(item_id))
        elif action_type == 'restart' and item_id:
            pprint(self.controller_client.restart(item_id))
        elif action_type == 'status' and item_id:
            pprint(self.controller_client.status(item_id))
        elif action_type == 'heartbeat' and item_id:
            pprint(self.controller_client.heartbeat(item_id))
        else:
            self._print_error("Invalid command parameters")

    def do_profile(self, args):
        """
        Perform operation on worker profiles

        Usage:
            profile list
                    show    <name>
                    remove  <name>

        Actions:
            list      List all profiles on the system
            remove    Remove the profile from the system
            show      Show the profile description

        Parameters:
            <name>   Name of the profile to perform the action on

        Examples:
            # Show profile 'sync_only'
            profile show sync_only
        """
        valid_actions = ['list', 'show', 'remove']
        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            item_id = None
        elif len(args) == 2:
            action_type, item_id = args
        else:
            self._print_error("Wrong number of arguments for profile command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for profile command.")
            return

        if action_type == 'list':
            for key in self.datastore.list_profile_keys():
                print key
        elif action_type == 'show' and item_id:
            pprint(self.datastore.get_profile(item_id))
        elif action_type == 'remove' and item_id:
            self.datastore.delete_profile(item_id)
            print "Profile '%s' removed."
        else:
            self._print_error("Invalid command parameters")

    def do_service(self, args):
        """
        Perform operation on the different services on the system

        Usage:
            service list
                    show    <name>
                    disable <name>
                    enable  <name>
                    remove  <name>

        Actions:
            list      List all services on the system
            disable   Disable the service in the system
            enable    Enable the service in the system
            remove    Remove the service from the system
            show      Show the service description

        Parameters:
            <name>   Name of the service to perform the action on

        Examples:
            # Show profile 'sync_only'
            profile show sync_only
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove']
        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            item_id = None
        elif len(args) == 2:
            action_type, item_id = args
        else:
            self._print_error("Wrong number of arguments for service command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for service command.")
            return

        if action_type == 'list':
            for key in self.datastore.list_service_keys():
                print key
        elif action_type == 'show' and item_id:
            pprint(self.datastore.get_service(item_id))
        elif action_type == 'disable' and item_id:
            item = self.datastore.get_service(item_id)
            if item:
                item['enabled'] = False
                self.datastore.save_service(item_id, item)
                print "%s was disabled" % item_id
            else:
                print "%s does not exist" % item_id
        elif action_type == 'enable' and item_id:
            item = self.datastore.get_service(item_id)
            if item:
                item['enabled'] = True
                self.datastore.save_service(item_id, item)
                print "%s was enabled" % item_id
            else:
                print "%s does not exist" % item_id
        elif action_type == 'remove' and item_id:
            self.datastore.delete_service(item_id)
            print "Service '%s' removed."
        else:
            self._print_error("Invalid command parameters")

    def do_signature(self, args):
        """
        Perform operation on a signature in the system

        Usage:
            signature change_status by_id    [force] <status_value> <id>
                      change_status by_query [force] <status_value> <query>
                      remove        <id>
                      show          <id>

        Actions:
            change_status  Change the status of a signature
            remove         Remove the signature from the system
            show           Show the signature description

        Parameters:
            <id>           ID of the signature to perform the action on
            <query>        Query to match the signature
            <status_value> New status value for the signature
            force          Automatically perform status change without asking for confirmation [optional]
            by_id          Use an ID to choose the signature
            by_query       Use a search query to choose the signatures

        Examples:
            # Change the status of all STAGING signatures to DEPLOYED
            signature change_status by_query DEPLOYED "meta.al_status:STAGING"
        """
        valid_actions = ['show', 'change_status', 'remove']
        args = self._parse_args(args)

        if 'force' in args:
            force = True
        else:
            force = False

        if len(args) == 2:
            action_type, item_id = args
            id_type = status = None
        elif len(args) == 4:
            action_type, id_type, status, item_id = args
        else:
            self._print_error("Wrong number of arguments for signature command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for signature command.")
            return

        if action_type == 'show' and item_id:
            pprint(self.datastore.get_signature(item_id))
        elif action_type == 'change_status' and item_id and id_type and status:
            if status not in YaraParser.STATUSES:
                self._print_error("\nInvalid status for action 'change_status' of signature command."
                                  "\n\nValid statuses are:\n%s" % "\n".join(YaraParser.STATUSES))
                return

            if id_type == 'by_id':
                update_signature_status(status, item_id, datastore=self.datastore)
                print "Signature '%s' was changed to status %s." % (item_id, status)
            elif id_type == 'by_query':
                pool = multiprocessing.Pool(processes=PROCESSES_COUNT, initializer=init)
                try:
                    cont = force
                    test_data = self.datastore._search_bucket(self.datastore.get_bucket("signature"),
                                                              item_id, start=0, rows=1)
                    if not test_data["total"]:
                        print "Nothing matches the query."
                        return

                    if not force:
                        print "\nNumber of items matching this query: %s\n\n" % test_data["total"]
                        print "This is an exemple of the signatures that will change status:\n"
                        print test_data['items'][0], "\n"
                        if self.prompt:
                            cont = raw_input("Are your sure you want to continue? (y/N) ")
                            cont = cont == "y"

                            if not cont:
                                print "\n**ABORTED**\n"
                                return
                        else:
                            print "You are not in interactive mode therefor the status change was not executed. " \
                                  "Add 'force' to your commandline to execute the status change."
                            return

                    if cont:
                        for data in self.datastore.stream_search("signature", item_id, fl="_yz_rk",
                                                                 item_buffer_size=COUNT_INCREMENT):
                            pool.apply_async(update_signature_status, (status, data["_yz_rk"]))
                except KeyboardInterrupt, e:
                    print "Interrupting jobs..."
                    pool.terminate()
                    pool.join()
                    raise e
                except Exception, e:
                    print "Something when wrong, retry!\n\n %s\n" % e
                else:
                    pool.close()
                    pool.join()
                    print "Signatures matching query '%s' were changed to status '%s'." % (item_id, status)
            else:
                self._print_error("Invalid action parameters for action 'change_status' of signature command.")

        elif action_type == 'remove' and item_id:
            self.datastore.delete_signature(item_id)
            print "Signature '%s' removed."
        else:
            self._print_error("Invalid command parameters")

    def do_user(self, args):
        """
        Perform operation on a user in the system

        Usage:
            user list
                 show        <uname>
                 disable     <uname>
                 enable      <uname>
                 set_admin   <uname>
                 unset_admin <uname>
                 remove      <uname>
                 unset_otp   <uname>
                 show_otp    <uname>

        Actions:
            list         List all the users
            show         Describe a user
            disable      Disable a user
            enable       Enable a user
            set_admin    Make a user admin
            unset_admin  Remove admin priviledges to a user
            remove       Remove a user
            unset_otp    Remove OTP Secret Token
            show_otp     Show current OTP Token

        Parameters:
            <uname>      Username of the user to perform the action on


        Examples:
            # Disable user 'user'
            user disable user
        """
        valid_actions = ['list', 'show', 'disable', 'enable', 'remove',
                         'set_admin', 'unset_admin', 'unset_otp', 'show_otp']
        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            item_id = None
        elif len(args) == 2:
            action_type, item_id = args
        else:
            self._print_error("Wrong number of arguments for user command.")
            return

        if action_type not in valid_actions:
            self._print_error("Invalid action for user command.")
            return

        if action_type == 'list':
            for key in [x for x in self.datastore.list_user_keys() if '_options' not in x and '_avatar' not in x]:
                print key
        elif action_type == 'show' and item_id:
            pprint(self.datastore.get_user(item_id))
        elif action_type == 'disable' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                item['is_active'] = False
                self.datastore.save_user(item_id, item)
                print "%s was disabled" % item_id
            else:
                print "%s does not exist" % item_id
        elif action_type == 'enable' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                item['is_active'] = True
                self.datastore.save_user(item_id, item)
                print "%s was enabled" % item_id
            else:
                print "%s does not exist" % item_id
        elif action_type == 'set_admin' and item_id:
                item = self.datastore.get_user(item_id)
                if item:
                    item['is_admin'] = True
                    self.datastore.save_user(item_id, item)
                    print "%s was added admin priviledges" % item_id
                else:
                    print "%s does not exist" % item_id
        elif action_type == 'unset_admin' and item_id:
                item = self.datastore.get_user(item_id)
                if item:
                    item['is_admin'] = False
                    self.datastore.save_user(item_id, item)
                    print "%s was removed admin priviledges" % item_id
                else:
                    print "%s does not exist" % item_id
        elif action_type == 'remove' and item_id:
            self.datastore.delete_user(item_id)
            print "User '%s' removed."
        elif action_type == 'unset_otp' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                item.pop('otp_sk', None)
                self.datastore.save_user(item_id, item)
                print "%s OTP secret key was removed" % item_id
            else:
                print "%s does not exist" % item_id
        elif action_type == 'show_otp' and item_id:
            item = self.datastore.get_user(item_id)
            if item:
                secret_key = item.get('otp_sk', None)
                if secret_key:
                    while True:
                        print '\r%s OTP Token:   %06d   %s%s' % (item_id, get_totp_token(secret_key),
                                                                 "█" * int(time.time() % 30),
                                                                 "░" * (29 - int(time.time() % 30))),
                        sys.__stdout__.flush()

                        time.sleep(1)
                else:
                    print "2FA not enabled for user %s" % item_id
            else:
                print "%s does not exist" % item_id
        else:
            self._print_error("Invalid command parameters")

    #
    # Index actions
    #
    def do_index(self, args):
        """
        Perform operations on the search index

        Usage:
            index commit   [<bucket>]
                  reindex  [<bucket>]

                  reset

        Actions:
            commit       Force SOLR to commit the index
            reindex      Read all keys and reindex them (Really slow)
            reset        Delete and recreate all search indexes

        Parameters:
            <bucket>     Bucket to do the opration on [optional]


        Examples:
            # Force commit on file bucket
            index commit file
            # Force commit on all bucket
            index commit
        """
        _reindex_map = {
            "alert": [self.datastore.list_alert_debug_keys, self.datastore.get_alert, self.datastore.save_alert,
                      None, None],
            "error": [self.datastore.list_error_debug_keys, self.datastore._get_bucket_item,
                      self.datastore._save_bucket_item, self.datastore.errors, None],
            "file": [self.datastore.list_file_debug_keys, self.datastore._get_bucket_item,
                     self.datastore._save_bucket_item, self.datastore.files, None],
            "filescore": [self.datastore.list_filescore_debug_keys, self.datastore._get_bucket_item,
                          self.datastore._save_bucket_item, self.datastore.filescores, None],
            "node": [self.datastore.list_node_debug_keys, self.datastore.get_node, self.datastore.save_node,
                     None, None],
            "profile": [self.datastore.list_profile_debug_keys, self.datastore.get_profile, self.datastore.save_profile,
                        None, None],
            "result": [self.datastore.list_result_debug_keys, self.datastore._get_bucket_item,
                       self.datastore._save_bucket_item, self.datastore.results, None],
            "signature": [self.datastore.list_signature_debug_keys, self.datastore.get_signature,
                          self.datastore.save_signature, None, None],
            "submission": [self.datastore.list_submission_debug_keys, self.datastore.get_submission,
                           self.datastore.save_submission, None, ["_tree", "_summary"]],
            "user": [self.datastore.list_user_debug_keys, self.datastore.get_user, self.datastore.save_user,
                     None, None],
            "workflow": [self.datastore.list_workflow_debug_keys, self.datastore.get_workflow,
                         self.datastore.save_workflow, None, None]
        }

        valid_buckets = sorted(self.datastore.INDEXED_BUCKET_LIST + self.datastore.ADMIN_INDEXED_BUCKET_LIST)
        valid_actions = ['commit', 'reindex', 'reset']

        args = self._parse_args(args)

        if len(args) == 1:
            action_type = args[0]
            bucket = None
        elif len(args) == 2:
            action_type, bucket = args
        else:
            self._print_error("Wrong number of arguments for index command.")
            return

        if action_type not in valid_actions:
            self._print_error("\nInvalid action specified: %s\n\n"
                              "Valid actions are:\n%s" % (action_type, "\n".join(valid_actions)))
            return

        if bucket and bucket not in valid_buckets:
            self._print_error("\nInvalid bucket specified: %s\n\n"
                              "Valid buckets are:\n%s" % (bucket, "\n".join(valid_buckets)))
            return

        if action_type == 'reindex':
            if bucket:
                reindex_args = _reindex_map[bucket]
                _reindex_template(bucket, reindex_args[0], reindex_args[1],
                                  reindex_args[2], reindex_args[3], reindex_args[4])
            else:
                for bucket in valid_buckets:
                    reindex_args = _reindex_map[bucket]
                    _reindex_template(bucket, reindex_args[0], reindex_args[1],
                                      reindex_args[2], reindex_args[3], reindex_args[4])
        elif action_type == 'commit':
            if bucket:
                self.datastore.commit_index(bucket)
                print "Index %s was commited." % bucket.upper()
            else:
                print "Forcing commit procedure for all indexes..."
                for bucket in valid_buckets:
                    print "    Index %s was commited." % bucket.upper()
                    self.datastore.commit_index(bucket)
                print "All indexes commited."
        elif action_type == 'reset':
            print "Recreating indexes:"

            indexes = [
                {'n_val': 0, 'name': 'filescore', 'schema': 'filescore'},
                {'n_val': 0, 'name': 'node', 'schema': 'node'},
                {'n_val': 0, 'name': 'signature', 'schema': 'signature'},
                {'n_val': 0, 'name': 'user', 'schema': 'user'},
                {'n_val': 0, 'name': 'file', 'schema': 'file'},
                {'n_val': 0, 'name': 'submission', 'schema': 'submission'},
                {'n_val': 0, 'name': 'error', 'schema': 'error'},
                {'n_val': 0, 'name': 'result', 'schema': 'result'},
                {'n_val': 0, 'name': 'profile', 'schema': 'profile'},
                {'n_val': 0, 'name': 'alert', 'schema': 'alert'},
            ]

            print "\tDisabling bucket association:"
            for index in indexes:
                bucket = self.datastore.client.bucket(index['name'], bucket_type="data")
                props = self.datastore.client.get_bucket_props(bucket)
                index['n_val'] = props['n_val']
                self.datastore.client.set_bucket_props(bucket, {"search_index": "_dont_index_",
                                                                "dvv_enabled": False,
                                                                "last_write_wins": True,
                                                                "allow_mult": False})
                print "\t\t%s" % index['name'].upper()

            print "\tDeleting indexes:"
            for index in indexes:
                try:
                    self.datastore.client.delete_search_index(index['name'])
                except:
                    pass
                print "\t\t%s" % index['name'].upper()

            print "\tCreating indexes:"
            for index in indexes:
                self.datastore.client.create_search_index(index['name'], schema=index['schema'], n_val=index['n_val'])
                print "\t\t%s" % index['name'].upper()

            print "\tAssociating bucket to index:"
            for index in indexes:
                bucket = self.datastore.client.bucket(index['name'], bucket_type="data")
                self.datastore.client.set_bucket_props(bucket, {"search_index": index['name']})
                print "\t\t%s" % index['name'].upper()

            print "All indexes successfully recreated!"

    #
    # Dispatcher actions
    #
    def do_dispatcher(self, args):
        """
        Perform operations on the running dispatchers

        Usage:
            dispatcher get_time      [<dispatcher_id>]
                       list_services [<dispatcher_id>]
                       outstanding   [<dispatcher_id>]

                       explain_state <sid>
                       services      <sid>

        Actions:
            get_time         Get the epoch time form the dispatchers
            list_services    List all registered services
            outstanding      List outstanding tasks
            explain_state    Explain the state of a given running submission
            services         List all outstanding services for a submission

        Parameters:
            <dispatcher_id>  ID of the dispatcher to query (Default: all)
            <sid>            Submission ID

        Examples:
            # List outstanding services for submission id 3204cf2f-9411-4ea6-b260-cbfe8f803793
            dispatcher service 3204cf2f-9411-4ea6-b260-cbfe8f803793
        """
        class DispatcherException(Exception):
            pass

        def _validate_dispatcher_id(i):
            try:
                i = int(i)
            except:
                raise DispatcherException("Not an integer")
            if i >= self.config.core.dispatcher.shards:
                raise DispatcherException("Out of range")

            return i

        args = self._parse_args(args)
        valid_actions = ['get_time', 'list_services', 'outstanding', 'services', 'explain_state']

        if len(args) == 1:
            action_type = args[0]
            item = None
        elif len(args) == 2:
            action_type, item = args
        else:
            self._print_error("Wrong number of arguments for dispatcher command.")
            return

        if action_type not in valid_actions:
            self._print_error("\nInvalid action specified: %s\n\n"
                              "Valid actions are:\n%s" % (action_type, "\n".join(valid_actions)))
            return

        try:
            if action_type == 'get_time':
                if item:

                    pprint(DispatchClient.get_system_time(_validate_dispatcher_id(item)))
                else:
                    for dispatcher in range(int(self.config.core.dispatcher.shards)):
                        pprint(DispatchClient.get_system_time(dispatcher))
            elif action_type == 'list_services':
                if item:
                    pprint(DispatchClient.list_service_info(_validate_dispatcher_id(item)))
                else:
                    for dispatcher in range(int(self.config.core.dispatcher.shards)):
                        pprint(DispatchClient.list_service_info(dispatcher))
            elif action_type == 'outstanding':
                if item:
                    pprint(DispatchClient.list_outstanding(_validate_dispatcher_id(item)))
                else:
                    for dispatcher in range(int(self.config.core.dispatcher.shards)):
                        pprint(DispatchClient.list_outstanding(dispatcher))
            elif action_type == 'services':
                if not item:
                    self._print_error("You must provide a SID")
                    return
                else:
                    pprint(DispatchClient.get_outstanding_services(item))
            elif action_type == 'explain_state':
                if not item:
                    self._print_error("You must provide a SID")
                    return
                else:
                    name = reply_queue_name('SID')
                    t = Task({}, **{
                        'sid': item,
                        'state': 'explain_state',
                        'watch_queue': name,
                    })
                    n = forge.determine_dispatcher(item)
                    forge.get_control_queue('control-queue-' + str(n)).push(t.raw)
                    nq = NamedQueue(name)
                    r = nq.pop(timeout=3000)
                    while r:
                        print '  ' * int(r['depth']) + str(r['srl']), str(r['message'])
                        r = nq.pop(timeout=3000)
                    if r is None:
                        print 'Timed out'
            else:
                self._print_error("Invalid command parameters")
        except DispatcherException, e:
            self._print_error("'%s' is not a valid dispatcher ID. [%s]" % (item, e.message))

    #
    # Wipe actions
    #
    def do_wipe(self, args):
        """
        Wipe all data from one or many buckets

        DO NOT USE ON PRODUCTION SYSTEM

        Usage:
            wipe bucket <bucket_name>
                 non_system
                 submission_data

        Actions:
            bucket           Single bucket wipe mode
            non_system       Delete all data from:
                                 alert
                                 emptyresult
                                 error
                                 file
                                 filescore
                                 result
                                 submission
                                 workflow
            submission_data  Delete all data from:
                                 emptyresult
                                 error
                                 file
                                 filescore
                                 result
                                 submission

        Parameters:
            <bucket_name>  Name of the bucket to wipe

        Examples:
            # Wipe all files
            wipe bucket file
        """
        args = self._parse_args(args)
        valid_actions = ['bucket', 'non_system', 'submission_data']

        if len(args) == 1:
            action_type = args[0]
            bucket = None
        elif len(args) == 2:
            action_type, bucket = args
        else:
            self._print_error("Wrong number of arguments for wipe command.")
            return

        if action_type not in valid_actions:
            self._print_error("\nInvalid action specified: %s\n\n"
                              "Valid actions are:\n%s" % (action_type, "\n".join(valid_actions)))
            return

        if action_type == 'bucket':
            if bucket not in self.wipe_map.keys():
                self._print_error("\nInvalid bucket: %s\n\n"
                                  "Valid buckets are:\n%s" % (bucket, "\n".join(self.wipe_map.keys())))
                return

            self.wipe_map[bucket]()
            print "Done wipping %s." % bucket
        elif action_type == 'non_system':
            for bucket in ['alert', 'emptyresult', 'error', 'file', 'filescore', 'result', 'submission', 'workflow']:
                self.wipe_map[bucket]()
                print "Done wipping %s." % bucket
        elif action_type == 'submission_data':
            for bucket in ['emptyresult', 'error', 'file', 'filescore', 'result', 'submission']:
                self.wipe_map[bucket]()
                print "Done wipping %s." % bucket
        else:
            self._print_error("Invalid command parameters")

    def do_data_reset(self, args):
        """
        Completely resets the database. Does a backup of the system data, wipe every buckets then
        restores the backup.

        DO NOT USE ON PRODUCTION SYSTEM

        Usage:
            data_reset [full]

        Parameters:
            full   Does not just wipe the system bucket, also wipe all submissions and results

        Examples:
            # Reset the database
            data_reset full
        """
        args = self._parse_args(args)

        if 'full' in args:
            full = True
        else:
            full = False

        backup_file = "/tmp/al_backup_%s" % str(uuid.uuid4())
        self.do_backup(backup_file)
        seed = self.datastore.get_blob('seed')

        for bucket in ['blob', 'node', 'profile', 'signature', 'user', 'workflow']:
            self.wipe_map[bucket]()

        if full:
            for bucket in ['alert', 'emptyresult', 'error', 'file', 'filescore', 'result', 'submission']:
                self.wipe_map[bucket]()

        self.do_index("commit")
        self.datastore.save_blob('seed', seed)
        self.do_restore(backup_file)
        shutil.rmtree(backup_file)

    def do_ui(self, args):
        """
        Perform UI related operations

        Usage:
            ui clear_sessions [username]
               rekey          [length]

        Parameters:
            clear_sessions     Removes all active sessions
            username           User to clear the sessions for
                               [optional, only use in clear_sessions]
            rekey              Create a new password encryption public/private key
            length             Length of the new public/private key
                               [optional, only use in rekey]

        Examples:
            # Clear sessions for user bob
            ui clear_sessions bob

            # Create a new key pair for encrypting passwords
            ui rekey
        """
        valid_func = ['clear_sessions', 'rekey']
        args = self._parse_args(args)

        if len(args) not in [1, 2]:
            self._print_error("Wrong number of arguments for restore command.")
            return

        func = args[0]
        if func not in valid_func:
            self._print_error("Invalid action '%s' for ui command." % func)
            return

        if func == 'clear_sessions':
            username = None
            if len(args) == 2:
                username = args[1]

            flsk_sess = Hash(
                "flask_sessions",
                host=config.core.redis.nonpersistent.host,
                port=config.core.redis.nonpersistent.port,
                db=config.core.redis.nonpersistent.db
            )

            if not username:
                flsk_sess.delete()
                print "All sessions where cleared."
            else:
                for k, v in flsk_sess.items().iteritems():
                    if v.get('username', None) == username:
                        print "Removing session: %s" % k
                        flsk_sess.pop(k)

                print "All sessions for user '%s' removed." % username

        elif func == 'rekey':
            length = None
            if len(args) == 2:
                try:
                    length = int(args[1])
                except ValueError:
                    self._print_error("Not a valid length: %s" % args[1])
                    return

            public_key, private_key = generate_async_keys(key_size=length or config.ui.get('rsa_key_size', 2048))
            self.datastore.save_blob('id_rsa.pub', public_key)
            self.datastore.save_blob('id_rsa', private_key)
            print "Rekeyed server. New public key:\n%s" % public_key


def print_banner():
    from assemblyline.al.common import banner
    from colors import red
    print red(banner.BANNER)


def shell_main():
    cli = ALCommandLineInterface(len(sys.argv) == 1)

    if len(sys.argv) != 1:
        cli.onecmd(" ".join([{True: '"%s"' % x, False: x}[" " in x] for x in sys.argv[1:]]))
    else:
        print_banner()
        cli.cmdloop()


if __name__ == '__main__':
    try:
        shell_main()
    except KeyboardInterrupt:
        exit()
