java PegwitCLI -i <test.pri >java.pub
fc java.pub test.pub
java PegwitCLI -e <test.jnk test.pub test.txt java.tx0
java PegwitCLI -s <test.pri test.txt >java.sig
fc java.sig test.sig
java PegwitCLI -v test.pub test.txt <java.sig
java PegwitCLI -d <test.pri java.tx0 java.pkd
fc java.pkd test.txt
java PegwitCLI -E <test.sig test.txt java.tx1
java PegwitCLI -D <test.sig java.tx1 java.ckd
fc java.ckd test.txt
java PegwitCLI -S test.txt <test.pri >java.tx2
fc java.tx2 test.tx2
java PegwitCLI -V test.pub java.tx2

java PegwitCLI -fe test.pub test.jnk <test.txt >java.tx3
java PegwitCLI -fd test.pri <java.tx3 
java PegwitCLI -fE test.sig <test.txt >java.tx4
fc java.tx4 test.tx4
java PegwitCLI -fD test.sig <java.tx4
java PegwitCLI -fS test.pri <test.txt >java.tx5
fc java.tx5 test.tx5
java PegwitCLI -fV test.pub <java.tx5

rem Here is a pubkey interspersed
rem with other text to demonstrate
rem the 'fold into .sig' capability
rem
java PegwitCLI -e <test.jnk test.bat test.txt javapub.tx0
java PegwitCLI -d <test.pri javapub.tx0 javapub.pkd
fc javapub.pkd test.txt
rem {pegwit v8 public key =cc23}
java PegwitCLI -v test.bat test.txt <test.sig
rem {ea8bc28aac71ee19befcb2beba}
java PegwitCLI -V test.bat test.tx2
rem {4b349cbdc020965e2411d48f6d}
java PegwitCLI -fe test.bat test.jnk <test.txt >javapub.tx3
java PegwitCLI -fd test.pri <javapub.tx3 > javapub.txt
fc javapub.txt test.txt
rem {fa28f4fd}
java PegwitCLI -fV test.bat <test.tx5
rem All done

