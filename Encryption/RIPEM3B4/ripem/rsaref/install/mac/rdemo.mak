#   File:       rsaref.make
#   Target:     rsaref
#   Sources:    {rsarefdir}SOURCE:DESC.C
#               {rsarefdir}SOURCE:DIGIT.C
#               {rsarefdir}SOURCE:MD2C.C
#               {rsarefdir}SOURCE:MD5C.C
#               {rsarefdir}SOURCE:NN.C
#               {rsarefdir}SOURCE:PRIME.C
#               {rsarefdir}SOURCE:RSA.C
#				{rsarefdir}SOURCE:R_DH.C
#               {rsarefdir}SOURCE:R_ENCODE.C
#               {rsarefdir}SOURCE:R_ENHANC.C
#               {rsarefdir}SOURCE:R_KEYGEN.C
#               {rsarefdir}SOURCE:R_RANDOM.C
#               {rsarefdir}SOURCE:R_STDLIB.C
#   Created:    Tuesday, February 25, 1992 5:12:56 PM

# Variable for user to specify the installed location. #
# This should be set to the folder that contains the folders SOURCE,RDEMO,TEST... #
rsarefdir = "{Boot}RSAREF:2_0.a1:"

objects = 	{rsarefdir}SOURCE:DESC.C.o ¶
			{rsarefdir}SOURCE:DIGIT.C.o ¶
			{rsarefdir}SOURCE:MD2C.C.o ¶
			{rsarefdir}SOURCE:MD5C.C.o ¶
			{rsarefdir}SOURCE:NN.C.o ¶
			{rsarefdir}SOURCE:PRIME.C.o ¶
			{rsarefdir}SOURCE:RSA.C.o ¶
			{rsarefdir}SOURCE:R_DH.C.o ¶
			{rsarefdir}SOURCE:R_ENCODE.C.o ¶
			{rsarefdir}SOURCE:R_ENHANC.C.o ¶
			{rsarefdir}SOURCE:R_KEYGEN.C.o ¶
			{rsarefdir}SOURCE:R_RANDOM.C.o ¶
			{rsarefdir}SOURCE:R_STDLIB.C.o

demoobjects =	rsaref.o {rsarefdir}RDEMO:RDEMO.C.o


rdemo ÄÄ {demoobjects} 
	Link -d -c 'MPS ' -t MPST ¶
		{demoobjects} ¶
		#"{CLibraries}"CSANELib.o ¶
		#"{CLibraries}"Math.o ¶
		#"{CLibraries}"Complex.o ¶
		"{CLibraries}"StdClib.o ¶
		"{Libraries}"Stubs.o ¶
		"{Libraries}"Runtime.o ¶
		"{Libraries}"Interface.o ¶
		#"{Libraries}"ToolLibs.o ¶
		-o rdemo
{rsarefdir}rdemo:RDEMO.C.o Ä rdemo.make {rsarefdir}rdemo:RDEMO.C
	 C -r -i {rsarefdir}SOURCE: {rsarefdir}rdemo:RDEMO.C

rsaref.o ÄÄ {objects} rdemo.make
	LIB -o RSAREF.o ¶
		{rsarefdir}SOURCE:DESC.C.o ¶
		{rsarefdir}SOURCE:DIGIT.C.o ¶
		{rsarefdir}SOURCE:MD2C.C.o ¶
		{rsarefdir}SOURCE:MD5C.C.o ¶
		{rsarefdir}SOURCE:NN.C.o ¶
		{rsarefdir}SOURCE:PRIME.C.o ¶
		{rsarefdir}SOURCE:RSA.C.o ¶
		{rsarefdir}SOURCE:R_DH.C.o ¶
		{rsarefdir}SOURCE:R_ENCODE.C.o ¶
		{rsarefdir}SOURCE:R_ENHANC.C.o ¶
		{rsarefdir}SOURCE:R_KEYGEN.C.o ¶
		{rsarefdir}SOURCE:R_RANDOM.C.o ¶
		{rsarefdir}SOURCE:R_STDLIB.C.o
{rsarefdir}SOURCE:DESC.C.o Ä rdemo.make {rsarefdir}SOURCE:DESC.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:DESC.C
{rsarefdir}SOURCE:DIGIT.C.o Ä rdemo.make {rsarefdir}SOURCE:DIGIT.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:DIGIT.C
{rsarefdir}SOURCE:MD2C.C.o Ä rdemo.make {rsarefdir}SOURCE:MD2C.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:MD2C.C
{rsarefdir}SOURCE:MD5C.C.o Ä rdemo.make {rsarefdir}SOURCE:MD5C.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:MD5C.C
{rsarefdir}SOURCE:NN.C.o Ä rdemo.make {rsarefdir}SOURCE:NN.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:NN.C
{rsarefdir}SOURCE:PRIME.C.o Ä rdemo.make {rsarefdir}SOURCE:PRIME.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:PRIME.C
{rsarefdir}SOURCE:RSA.C.o Ä rdemo.make {rsarefdir}SOURCE:RSA.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:RSA.C
{rsarefdir}SOURCE:R_DH.C.o Ä rdemo.make {rsarefdir}SOURCE:R_DH.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:R_DH.C
{rsarefdir}SOURCE:R_ENCODE.C.o Ä rdemo.make {rsarefdir}SOURCE:R_ENCODE.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:R_ENCODE.C
{rsarefdir}SOURCE:R_ENHANC.C.o Ä rdemo.make {rsarefdir}SOURCE:R_ENHANC.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:R_ENHANC.C
{rsarefdir}SOURCE:R_KEYGEN.C.o Ä rdemo.make {rsarefdir}SOURCE:R_KEYGEN.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:R_KEYGEN.C
{rsarefdir}SOURCE:R_RANDOM.C.o Ä rdemo.make {rsarefdir}SOURCE:R_RANDOM.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:R_RANDOM.C
{rsarefdir}SOURCE:R_STDLIB.C.o Ä rdemo.make {rsarefdir}SOURCE:R_STDLIB.C
	 C -r -d PROTOTYPES=1 {rsarefdir}SOURCE:R_STDLIB.C

