gcc -c -O3 -I../rsaref/source adduser.c
gcc -c -O3 -I../rsaref/source bemparse.c
gcc -c -O3 -I../rsaref/source crackhed.c
gcc -c -O3 -I../rsaref/source derkey.c
gcc -c -O3 -I../rsaref/source getopt.c
gcc -c -O3 -I../rsaref/source getsys.c
gcc -c -O3 -I../rsaref/source hexbin.c
gcc -c -O3 -I../rsaref/source keyder.c
gcc -c -O3 -I../rsaref/source keyman.c
gcc -c -O3 -I../rsaref/source list.c
gcc -c -O3 -I../rsaref/source parsit.c
gcc -c -O3 -I../rsaref/source prencode.c
gcc -c -O3 -I../rsaref/source pubinfo.c
gcc -c -O3 -I../rsaref/source rdwrmsg.c
gcc -c -O3 -I../rsaref/source ripemmai.c
gcc -c -O3 -I../rsaref/source ripemsoc.c
gcc -c -O3 -I../rsaref/source strutil.c
gcc -c -O3 -I../rsaref/source usage.c
gcc -c -O3 -I../rsaref/source usagemsg.c
gcc -o ripem @ripemgcc.lrf
copy /b \gcc\bin\go32.exe+ripem ripem.exe
