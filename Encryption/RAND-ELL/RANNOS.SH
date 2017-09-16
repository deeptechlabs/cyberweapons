#/bin/sh
#
#  This shell script gives an output of random-like bytes, after the
#  first set.  The first bytes are readable text from the system,
#  giving numbers of processes created.  The sequence continues
#  forever.
#
#  To remove the opening predictable bytes, you can use the command dd.
#  If this shell script is named ran.sh, you would then use:
#
#	ran.sh | dd skip=1 | {user-of-random-bytes-from-stdin}
# or
#	ran.sh | dd skip=1 > {pipe-file-for-random-bytes}
#


# first, create a pipe file, just for this shell script
/usr/etc/mknod rpipe.aa895c1cbd6 p

(date;ps -aux)|gzip -c|tran|ranG|ranH -n 2 -x 20 >rpipe.aa895c1cbd6 &
(netstat;date)|gzip -c|tran|ranG md5|ranM rpipe.aa895c1cbd6 &

sleep 15
rm rpipe.aa895c1cbd6
