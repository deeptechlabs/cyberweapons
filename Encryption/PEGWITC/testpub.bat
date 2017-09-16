rem Here is a pubkey interspersed
rem with other text to demonstrate
rem the 'fold into .sig' capability
rem
pegwit -e <test.jnk testpub.bat test.txt testpub.tx0
pegwit -d <test.pri testpub.tx0 con
rem {pegwit v8 public key =cc23}
pegwit -v testpub.bat test.txt <test.sig
rem {ea8bc28aac71ee19befcb2beba}
pegwit -V testpub.bat test.tx2
rem {4b349cbdc020965e2411d48f6d}
pegwit -fe testpub.bat test.jnk <test.txt >testpub.tx3
pegwit -fd test.pri <testpub.tx3 
rem {fa28f4fd}
pegwit -fV testpub.bat <test.tx5
rem All done