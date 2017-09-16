pegwit -i <test.pri >test.pub
pegwit -e <test.jnk test.pub test.txt test.tx0
pegwit -s <test.pri test.txt >test.sig
pegwit -v test.pub test.txt <test.sig
pegwit -d <test.pri test.tx0 con
pegwit -E <test.sig test.txt test.tx1
pegwit -D <test.sig test.tx1 con
pegwit -S test.txt <test.pri >test.tx2
pegwit -V test.pub test.tx2

pegwit -fe test.pub test.jnk <test.txt >test.tx3
pegwit -fd test.pri <test.tx3 
pegwit -fE test.sig <test.txt >test.tx4
pegwit -fD test.sig <test.tx4
pegwit -fS test.pri <test.txt >test.tx5
pegwit -fV test.pub <test.tx5
