/*
  Combining Linear Congruential Generators
*/

/*
L'Ecuyer gives [528] a generator for 32-bit computers:
       static s1, s2;
       FUNCTION combined-LCG : REAL;
               VAR Z,k : INTEGER
               BEGIN
                      k := s1 DIV 53668;
                      s1 := 40014 * (s1 - k * 53668) - k * 12211;
                      IF s1 < 0 THEN s1 := s1 + 2147483563;
                      k := s2 DIV 52774;
                      s2 := 40692 * (s2 - k * 52774) - k * 3791;
                      IF s2 < 0 THEN s2 := s2 + 2147483399;
                      Z := s1 - s2;
                      if Z < 1 THEN Z := Z + 2147483562;
                      combined-LCG := Z * 4.656613E-10
               END

The variable s1 needs an initial value between 1 and 2147483562;
the variable s2 needs an initial value between 1 and 2147483398.
The generator has a period somewhere in the neighborhood of 10**18.

If you only have a 16-bit computer, use this generator instead:
       FUNCTION combined-LCG : REAL;
               VAR Z,k : INTEGER
               BEGIN
                      k := s1 DIV 206;
                      s1 := 157 * (s1 - k * 206) - k * 21;
                      IF s1 < 0 THEN s1 := s1 + 32363;
                      k := s2 DIV 217;
                      s2 := 146 * (s2 - k * 217) - k * 45;
                      IF s2 < 0 THEN s2 := s2 + 31727;
                      k := s3 DIV 222;
                      s3 := 142 * (s3 - k * 222) - k * 133;
                      IF s3 < 0 THEN s3 := s3 + 31657;
                      Z := s1 - s2;
                      IF Z > 706 THEN Z := Z - 32362;
                      Z := Z + s3;
                      if Z < 1 THEN Z := Z + 32362;
                      combined-LCG := Z * 3.0899E-5
               END

*****

The C code for this LFSR looks like:

       int LFSR ()  {
               static unsigned long ShiftRegister;
               ShiftRegister = (( (ShiftRegister >> 7)
                                ^ (ShiftRegister >> 5)
                                ^ (ShiftRegister >> 3)
                                ^ (ShiftRegister >> 2)
                                ^ (ShiftRegister >> 1)
                                ^ ShiftRegister)
                               & 0x00000001)
                               << 31
                               | (ShiftRegister >> 1);
               return ShiftRegister & 0x00000001;
       }
*/
