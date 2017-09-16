all: hill0 hill.exe kappa
hill0: hill0.c table.i
	cc -o hill0 hill0.c
hill.exe: hill0.c table.i
	cc -DDOS -dos -o hill.exe hill0.c
kappa: kappa.c
install: hill hill0
	mv hill hill0 /usr/lbin
