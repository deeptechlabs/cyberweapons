#	Makefile -- for	"tot_info" utility (export version)
 
#	last edit:	91/04/01	D A Gwyn
 
#	Inspect	and adjust the following configurable parameters;
#	then invoke "make typeset" to print the	documentation,
#	and "make test"	to build and test the tot_info utility.
 
#	Although the system configuration header "std.h" is suitable
#	for many systems as distributed, in some environments you may
#	need to	edit it	to properly fit	your system characteristics.
 
#	If your	Documenter's WorkBench installation does not support
#	the CW and CB constant-width fonts, you	will need to edit the
#	"manual	page" source files tot_info.1, chisq.3,	and gamma.3
#	to redefine the	cW and cB string variables (around line	11).
 
#	You may	want to	also "make chisq.o" then put the object	modules
#	chisq.o, gamma.o, and info.o into a library archive and	the
#	header files chisq.h, gamma.h, and std.h into a	standard include
#	directory, for convenience in using these functions in your own
#	applications.
 
# Configurable parameters, if required:
EQN		= eqn -Ti300		# "eqn"	preprocessor and options
TROFF		= nroff	-Ti300 -man	# "troff" text formatter and options
POST		= | dimp -Pim124	# troff	postprocessor, if required
RM		= -rm -f		# "benign" invocation of "rm"
CC		= cc			# C compiler
DEBUG		= # -g			# debugging support option for $(CC)
INCLUDE		= # -I.			# specifies header directories to $(CC)
OPTIMIZE	= # -O			# optimization option(s) for $(CC)
PROFILE		= # -p			# profiling option for $(CC)
SYSTEM		= # -hstdc		# special options for $(CC)
LDOPTS		= # -n			# options for linking using $(CC)
LDLIBS		= -lm			# standard math	library
LINT		= lint			# source code quality checker
LINTOPTS	= -p			# options for $(LINT)
LINTLIBS	= -lm			# additional libraries for $(LINT)
CFLOW		= cflow			# call graph utility and options
CXREF		= cxref	-c -s -w132	# cross-reference utility and options
 
CFLAGS	= $(DEBUG) $(INCLUDE) $(OPTIMIZE) $(PROFILE) $(SYSTEM)
LDFLAGS	= $(DEBUG) $(LDOPTS) $(PROFILE)
LNFLAGS	= $(INCLUDE) $(LINTOPTS)
 
all:		tot_info
 
tot_info:	tot_info.o gamma.o info.o
	$(CC) $(LDFLAGS) -o tot_info tot_info.o	gamma.o	info.o $(LDLIBS)
 
tot_info.o:	chisq.h	gamma.h	std.h
	$(CC) $(CFLAGS)	-c tot_info.c
 
g_test:		g_test.o gamma.o
	$(CC) $(LDFLAGS) -o g_test g_test.o gamma.o $(LDLIBS)
 
g_test.o:	gamma.h	std.h
	$(CC) $(CFLAGS)	-c g_test.c
 
gamma.o:	gamma.h	std.h
	$(CC) $(CFLAGS)	-c gamma.c
 
info.o:		chisq.h	std.h
	$(CC) $(CFLAGS)	-c info.c
 
# The following	is not used by "tot_info"; however, it is referred to
# in the documentation and may be of interest, so I included it	too:
chisq.o:	chisq.h	std.h
	$(CC) $(CFLAGS)	-c chisq.c
 
typeset:	tot_info.1 chisq.3 gamma.3
	$(EQN) tot_info.1 | $(TROFF) $(POST)
	$(EQN) chisq.3 | $(TROFF) $(POST)
	$(EQN) gamma.3 | $(TROFF) $(POST)
 
lint:		g_test.c tot_info.c chisq.c gamma.c info.c chisq.h gamma.h std.h
	echo '========== tot_info ==========' >	lint
	$(LINT)	$(LNFLAGS) tot_info.c gamma.c info.c chisq.c $(LINTLIBS) >> lint
	echo '========== g_test	==========' >> lint
	$(LINT)	$(LNFLAGS) g_test.c gamma.c chisq.c $(LINTLIBS)	>> lint
 
flow:		g_test.c tot_info.c chisq.c gamma.c info.c chisq.h gamma.h std.h
	echo '========== tot_info ==========' >	flow
	$(CFLOW) tot_info.c gamma.c info.c >> flow
	echo '========== g_test	==========' >> flow
	$(CFLOW) g_test.c gamma.c chisq.c >> flow
 
xref:		g_test.c tot_info.c chisq.c gamma.c info.c chisq.h gamma.h std.h
	echo '========== tot_info ==========' >	xref
	$(CXREF) tot_info.c gamma.c info.c >> xref
	echo '========== g_test	==========' >> xref
	$(CXREF) g_test.c gamma.c chisq.c >> xref
 
test:		gamma_test info_test
 
gamma_test:	g_test
	./g_test	# returns success/failure indication as	exit status
 
info_test:	tot_info tot_info.in tot_info.exp
	./tot_info < tot_info.in > tot_info.out	2> tot_info.err
	@if cmp	-s tot_info.exp	tot_info.out ; \
	then	echo 'Tested okay!' ; \
	else	echo '*** Test failed; differences:' ; \
		diff tot_info.exp tot_info.out ; \
		exit 1 ; \
	fi
 
clean:
	$(RM) lint flow	xref core a.out	mon.out	nohup.out
	$(RM) g_test g_test.o tot_info.o tot_info.out tot_info.err
 
clobber:	clean
	$(RM) tot_info chisq.o gamma.o info.o
