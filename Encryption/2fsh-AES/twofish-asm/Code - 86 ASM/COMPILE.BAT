@rem To choose an option, use
@rem     compile FULL_KEY   (default)
@rem     compile PART_KEY   
@rem     compile MIN_KEY    
@rem     compile ZERO_KEY   
@rem     compile COMPILE_KEY
@if [%1]==[] %0 FULL_KEY 
bcc32 -Tt -TD%1 -D%1 -Oi -5 -v -A -a4 -O2 -DUSE_ASM tst2fish.c twofish2.c 2fish_86.asm cputype.asm
