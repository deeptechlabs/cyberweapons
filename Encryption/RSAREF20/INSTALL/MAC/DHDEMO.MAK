#   File:       dhdemo.make
#   Target:     dhdemo
#   Sources:    'QA Centris:RSAREF:2_0.A1:RDEMO:DHDEMO.C'
#   Created:    Saturday, March 19, 1994 2:29:00 PM

# Variable for user to specify the installed location. #
# This should be set to the folder that contains the folders SOURCE,RDEMO,TEST... #
rsarefdir = "{Boot}RSAREF:2_0.a1:"


OBJECTS = RSAREF.o 'QA Centris:RSAREF:2_0.A1:RDEMO:DHDEMO.C.o'

dhdemo ÄÄ dhdemo.make {OBJECTS}
	Link -d -c 'MPS ' -t MPST ¶
		{OBJECTS} ¶
		#"{CLibraries}"CSANELib.o ¶
		#"{CLibraries}"Math.o ¶
		#"{CLibraries}"Complex.o ¶
		"{CLibraries}"StdClib.o ¶
		"{Libraries}"Runtime.o ¶
		"{Libraries}"Interface.o ¶
		-o dhdemo
'QA Centris:RSAREF:2_0.A1:RDEMO:DHDEMO.C.o' Ä dhdemo.make 'QA Centris:RSAREF:2_0.A1:RDEMO:DHDEMO.C'
	 C -r -i {rsarefdir}SOURCE: 'QA Centris:RSAREF:2_0.A1:RDEMO:DHDEMO.C'
