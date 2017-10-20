#!/usr/bin/env python
import subprocess

from assemblyline.common.reaper import set_death_signal

WRITER_COUNT = 20
READER_COUNT = 15
EXPIRY_SUBMISSION_COUNT = 1
EXPIRY_FILE_COUNT = 2
EXPIRY_RESULT_COUNT = 10


if __name__ == "__main__":
    print "Welcome to Assemblyline's Riak benchmark utility\n"

    value = raw_input("What are the IPs for the Riak nodes you want to benchmark? (space seperated): ")
    ips = value.strip().split(" ")

    readers_lookback_hours = raw_input("How far back should the readers read in hours? [2]: ")
    try:
        readers_lookback_hours = int(readers_lookback_hours)
    except ValueError:
        readers_lookback_hours = 2

    htl = raw_input("How many hours should the data live before being expired? [3]: ")
    try:
        htl = int(htl)
    except ValueError:
        htl = 3

    print "\nLaunching workers against Riak node(s): %s\n" % " | ".join(ips)

    for x in xrange(WRITER_COUNT):
        subprocess.Popen(['python', '-W', 'ignore', 'writer.py', str(htl)] + ips, preexec_fn=set_death_signal())
        print "\twriter_%s started." % x

    for x in xrange(READER_COUNT):
        subprocess.Popen(['python', '-W', 'ignore', 'reader.py', str(readers_lookback_hours)] + ips,
                         preexec_fn=set_death_signal())
        print "\treader_%s started." % x

    for x in xrange(EXPIRY_SUBMISSION_COUNT):
        subprocess.Popen(['python', '-W', 'ignore', 'expiry.py', 'submission'] + ips, preexec_fn=set_death_signal())
        print "\texpiry_submission_%s started." % x

    for x in xrange(EXPIRY_FILE_COUNT):
        subprocess.Popen(['python', '-W', 'ignore', 'expiry.py', 'file'] + ips, preexec_fn=set_death_signal())
        print "\texpiry_file_%s started." % x

    for x in xrange(EXPIRY_RESULT_COUNT):
        subprocess.Popen(['python', '-W', 'ignore', 'expiry.py', 'result'] + ips, preexec_fn=set_death_signal())
        print "\texpiry_result_%s started." % x

    print "All workers started!\n"
    raw_input("Press enter to stop all workers.")