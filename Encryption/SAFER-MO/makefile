# OPTIONAL DEFINES
# ================
#
#   NOT_ANSI_C     if defined the preprocessed source code is Kernighan & 
#                  Ritchie C code, otherwise it is ANSI C and C++ code.
#
#   TIME           if defined the user-command 'safer' has the additional option
#                  '-m' to measure the encryption speed.
#
#   HELP           if defined the user-command 'safer' has the additional option
#                  '-help' to write a help text to standard output.
#
#   GETPASS        if defined the user-command 'safer' interactively requests a
#                  key from the user when the key is not already included in the
#                  command line. This define may not work on systems other than
#                  UNIX.
#
# COMMANDS
# ========
#
#   make           is used to build user-command 'safer'
#   make checking  is used to check the correctness of user-command 'safer'
#
# YOUR JOB
# ========
#
#   Ensure the next line specifies which C compiler you are using.

CC      = gcc -DTIME -DGETPASS -DHELP -O2 -Wall

# DO NOT MODIFY THE FOLLOWING

all:	safer

safer:	safercmd.c safer.c safer.h
	$(CC) -o safer safercmd.c safer.c

check:	check.c
	$(CC) -o check check.c

checking:	safer check
	check
