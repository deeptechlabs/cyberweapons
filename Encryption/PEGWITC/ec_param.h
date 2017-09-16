/*
	GF_M	dimension of the large finite field (GF_M = GF_L*GF_K)
	GF_L	dimension of the small finite field
	GF_K	degree of the large field reduction trinomial
	GF_T	intermediate power of the reduction trinomial
	GF_RP	reduction polynomial for the small field (truncated)
	GF_NZT	element of the large field with nonzero trace
	GF_TM0	size of trace mask
	GF_TM1	1st nonzero element of trace mask
	GF_TM2	2nd nonzero element of trace mask
	EC_B	scalar term of elliptic curve equation (y^2 + xy = x^3 + EC_B)
*/

#define GF_M		255 /* choose this value from the list below */

#if GF_M == 24

#define GF_L	      8
#define GF_K	      3
#define GF_T	      1
#define GF_RP	0x001dU
#define GF_NZT	0x0020U
#define GF_TM0	      1
#define GF_TM1	0x0020U
#define EC_B	0x006eU

#elif GF_M == 30

#define GF_L	     10
#define GF_K	      3
#define GF_T	      1
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x000cU

#elif GF_M == 33

#define GF_L	     11
#define GF_K	      3
#define GF_T	      1
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0065U

#elif GF_M == 39

#define GF_L	     13
#define GF_K	      3
#define GF_T	      1
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0001U

#elif GF_M == 40

#define GF_L	      8
#define GF_K	      5
#define GF_T	      2
#define GF_RP	0x001dU
#define GF_NZT	0x0020U
#define GF_TM0	      4
#define GF_TM1	0x0020U
#define GF_TM2	0x0020U
#define EC_B	0x006eU

#elif GF_M == 42

#define GF_L	     14
#define GF_K	      3
#define GF_T	      1
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x026eU

#elif GF_M == 45

#define GF_L	      9
#define GF_K	      5
#define GF_T	      2
#define GF_RP	0x0011U
#define GF_TM0	      4
#define GF_TM1	0x0021U
#define GF_TM2	0x0021U
#define EC_B	0x000bU

#elif GF_M == 48

#define GF_L	     16
#define GF_K	      3
#define GF_T	      1
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0b56U

#elif GF_M == 55

#define GF_L	     11
#define GF_K	      5
#define GF_T	      2
#define GF_RP	0x0005U
#define GF_TM0	      4
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x000eU

#elif GF_M == 56

#define GF_L	      8
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x001dU
#define GF_NZT	0x0020U
#define GF_TM0	      1
#define GF_TM1	0x0020U
#define EC_B	0x0029U

#elif GF_M == 60

#define GF_L	     12
#define GF_K	      5
#define GF_T	      2
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      4
#define GF_TM1	0x0800U
#define GF_TM2	0x0800U
#define EC_B	0x081fU

#elif GF_M == 63

#define GF_L	      9
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x002bU

#elif GF_M == 65

#define GF_L	     13
#define GF_K	      5
#define GF_T	      2
#define GF_RP	0x001bU
#define GF_TM0	      4
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x01a2U

#elif GF_M == 70

#define GF_L	     10
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x009aU

#elif GF_M == 77

#define GF_L	     11
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0017U

#elif GF_M == 80

#define GF_L	     16
#define GF_K	      5
#define GF_T	      2
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      4
#define GF_TM1	0x2800U
#define GF_TM2	0x2800U
#define EC_B	0x0fadU

#elif GF_M == 84

#define GF_L	     12
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x0801U

#elif GF_M == 91

#define GF_L	     13
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x007cU

#elif GF_M == 99

#define GF_L	      9
#define GF_K	     11
#define GF_T	      2
#define GF_RP	0x0011U
#define GF_TM0	     10
#define GF_TM1	0x0021U
#define GF_TM2	0x0021U
#define EC_B	0x000dU

#elif GF_M == 105

#define GF_L	     15
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x03d1U

#elif GF_M == 110

#define GF_L	     10
#define GF_K	     11
#define GF_T	      2
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	     10
#define GF_TM1	0x0080U
#define GF_TM2	0x0080U
#define EC_B	0x008bU

#elif GF_M == 112

#define GF_L	     16
#define GF_K	      7
#define GF_T	      1
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0b56U

#elif GF_M == 132

#define GF_L	     12
#define GF_K	     11
#define GF_T	      2
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	     10
#define GF_TM1	0x0800U
#define GF_TM2	0x0800U
#define EC_B	0x0823U

#elif GF_M == 136

#define GF_L	      8
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x001dU
#define GF_NZT	0x0020U
#define GF_TM0	      1
#define GF_TM1	0x0020U
#define EC_B	0x0020U

#elif GF_M == 143

#define GF_L	     13
#define GF_K	     11
#define GF_T	      2
#define GF_RP	0x001bU
#define GF_TM0	     10
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x0305U

#elif GF_M == 153

#define GF_L	      9
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x0013U

#elif GF_M == 154

#define GF_L	     14
#define GF_K	     11
#define GF_T	      2
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	     10
#define GF_TM1	0x2a00U
#define GF_TM2	0x2a00U
#define EC_B	0x0092U

#elif GF_M == 165

#define GF_L	     15
#define GF_K	     11
#define GF_T	      2
#define GF_RP	0x0003U
#define GF_TM0	     10
#define GF_TM1	0x0001U
#define GF_TM2	0x0001U
#define EC_B	0x008cU

#elif GF_M == 170

#define GF_L	     10
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x0030U

#elif GF_M == 176

#define GF_L	     16
#define GF_K	     11
#define GF_T	      2
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	     10
#define GF_TM1	0x2800U
#define GF_TM2	0x2800U
#define EC_B	0x001aU

#elif GF_M == 187

#define GF_L	     11
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x003aU

#elif GF_M == 204

#define GF_L	     12
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x0804U

#elif GF_M == 207

#define GF_L	      9
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x009bU

#elif GF_M == 221

#define GF_L	     13
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0305U

#elif GF_M == 230

#define GF_L	     10
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x000cU

#elif GF_M == 238

#define GF_L	     14
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x011bU

#elif GF_M == 253

#define GF_L	     11
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x001fU

#elif GF_M == 255

#define GF_L	     15
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x00a1U

#elif GF_M == 261

#define GF_L	      9
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x0011U
#define GF_TM0	     28
#define GF_TM1	0x0021U
#define GF_TM2	0x0021U
#define EC_B	0x0025U

#elif GF_M == 272

#define GF_L	     16
#define GF_K	     17
#define GF_T	      3
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0803U

#elif GF_M == 276

#define GF_L	     12
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x000cU

#elif GF_M == 279

#define GF_L	      9
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x000cU

#elif GF_M == 290

#define GF_L	     10
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	     28
#define GF_TM1	0x0080U
#define GF_TM2	0x0080U
#define EC_B	0x000cU

#elif GF_M == 299

#define GF_L	     13
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0214U

#elif GF_M == 310

#define GF_L	     10
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x0002U

#elif GF_M == 319

#define GF_L	     11
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x0005U
#define GF_TM0	     28
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x003aU

#elif GF_M == 322

#define GF_L	     14
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x024dU

#elif GF_M == 341

#define GF_L	     11
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x000eU

#elif GF_M == 345

#define GF_L	     15
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x0003U

#elif GF_M == 348

#define GF_L	     12
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	     28
#define GF_TM1	0x0800U
#define GF_TM2	0x0800U
#define EC_B	0x0013U

#elif GF_M == 368

#define GF_L	     16
#define GF_K	     23
#define GF_T	      5
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x094cU

#elif GF_M == 372

#define GF_L	     12
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x0007U

#elif GF_M == 377

#define GF_L	     13
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x001bU
#define GF_TM0	     28
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x0091U

#elif GF_M == 403

#define GF_L	     13
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x007cU

#elif GF_M == 406

#define GF_L	     14
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	     28
#define GF_TM1	0x2a00U
#define GF_TM2	0x2a00U
#define EC_B	0x0027U

#elif GF_M == 410

#define GF_L	     10
#define GF_K	     41
#define GF_T	      3
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x00abU

#elif GF_M == 423

#define GF_L	      9
#define GF_K	     47
#define GF_T	      5
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x0009U

#elif GF_M == 434

#define GF_L	     14
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x0043U

#elif GF_M == 435

#define GF_L	     15
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x0003U
#define GF_TM0	     28
#define GF_TM1	0x0001U
#define GF_TM2	0x0001U
#define EC_B	0x00ccU

#elif GF_M == 451

#define GF_L	     11
#define GF_K	     41
#define GF_T	      3
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x006aU

#elif GF_M == 464

#define GF_L	     16
#define GF_K	     29
#define GF_T	      2
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	     28
#define GF_TM1	0x2800U
#define GF_TM2	0x2800U
#define EC_B	0x0846U

#elif GF_M == 465

#define GF_L	     15
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x01a5U

#elif GF_M == 470

#define GF_L	     10
#define GF_K	     47
#define GF_T	      5
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x000bU

#elif GF_M == 492

#define GF_L	     12
#define GF_K	     41
#define GF_T	      3
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x0830U

#elif GF_M == 496

#define GF_L	     16
#define GF_K	     31
#define GF_T	      3
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x080bU

#elif GF_M == 517

#define GF_L	     11
#define GF_K	     47
#define GF_T	      5
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x001dU

#elif GF_M == 533

#define GF_L	     13
#define GF_K	     41
#define GF_T	      3
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x006aU

#elif GF_M == 564

#define GF_L	     12
#define GF_K	     47
#define GF_T	      5
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x0800U

#elif GF_M == 568

#define GF_L	      8
#define GF_K	     71
#define GF_T	      6
#define GF_RP	0x001dU
#define GF_NZT	0x0020U
#define GF_TM0	     66
#define GF_TM1	0x0020U
#define GF_TM2	0x0020U
#define EC_B	0x0020U

#elif GF_M == 574

#define GF_L	     14
#define GF_K	     41
#define GF_T	      3
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x000eU

#elif GF_M == 611

#define GF_L	     13
#define GF_K	     47
#define GF_T	      5
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x000aU

#elif GF_M == 615

#define GF_L	     15
#define GF_K	     41
#define GF_T	      3
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x05b2U

#elif GF_M == 639

#define GF_L	      9
#define GF_K	     71
#define GF_T	      6
#define GF_RP	0x0011U
#define GF_TM0	     66
#define GF_TM1	0x0021U
#define GF_TM2	0x0021U
#define EC_B	0x0019U

#elif GF_M == 656

#define GF_L	     16
#define GF_K	     41
#define GF_T	      3
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0422U

#elif GF_M == 657

#define GF_L	      9
#define GF_K	     73
#define GF_T	     25
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x0019U

#elif GF_M == 705

#define GF_L	     15
#define GF_K	     47
#define GF_T	      5
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x008cU

#elif GF_M == 730

#define GF_L	     10
#define GF_K	     73
#define GF_T	     25
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x0007U

#elif GF_M == 752

#define GF_L	     16
#define GF_K	     47
#define GF_T	      5
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0a0eU

#elif GF_M == 781

#define GF_L	     11
#define GF_K	     71
#define GF_T	      6
#define GF_RP	0x0005U
#define GF_TM0	     66
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x0009U

#elif GF_M == 904

#define GF_L	      8
#define GF_K	    113
#define GF_T	      9
#define GF_RP	0x001dU
#define GF_NZT	0x0020U
#define GF_TM0	      1
#define GF_TM1	0x0020U
#define EC_B	0x001fU

#elif GF_M == 927

#define GF_L	      9
#define GF_K	    103
#define GF_T	      9
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x0002U

#elif GF_M == 948

#define GF_L	     12
#define GF_K	     79
#define GF_T	      9
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x0017U

#elif GF_M == 949

#define GF_L	     13
#define GF_K	     73
#define GF_T	     25
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0006U

#elif GF_M == 979

#define GF_L	     11
#define GF_K	     89
#define GF_T	     38
#define GF_RP	0x0005U
#define GF_TM0	     52
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x0007U

#elif GF_M == 994

#define GF_L	     14
#define GF_K	     71
#define GF_T	      6
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	     66
#define GF_TM1	0x2a00U
#define GF_TM2	0x2a00U
#define EC_B	0x0239U

#elif GF_M == 1022

#define GF_L	     14
#define GF_K	     73
#define GF_T	     25
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x011bU

#elif GF_M == 1027

#define GF_L	     13
#define GF_K	     79
#define GF_T	      9
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0021U

#elif GF_M == 1067

#define GF_L	     11
#define GF_K	     97
#define GF_T	      6
#define GF_RP	0x0005U
#define GF_TM0	     92
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x000fU

#elif GF_M == 1095

#define GF_L	     15
#define GF_K	     73
#define GF_T	     25
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x00e2U

#elif GF_M == 1136

#define GF_L	     16
#define GF_K	     71
#define GF_T	      6
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	     66
#define GF_TM1	0x2800U
#define GF_TM2	0x2800U
#define EC_B	0x00f1U

#elif GF_M == 1168

#define GF_L	     16
#define GF_K	     73
#define GF_T	     25
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x08b3U

#elif GF_M == 1185

#define GF_L	     15
#define GF_K	     79
#define GF_T	      9
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x0089U

#elif GF_M == 1236

#define GF_L	     12
#define GF_K	    103
#define GF_T	      9
#define GF_RP	0x0053U
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x0800U
#define EC_B	0x0006U

#elif GF_M == 1246

#define GF_L	     14
#define GF_K	     89
#define GF_T	     38
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	     52
#define GF_TM1	0x2a00U
#define GF_TM2	0x2a00U
#define EC_B	0x0222U

#elif GF_M == 1261

#define GF_L	     13
#define GF_K	     97
#define GF_T	      6
#define GF_RP	0x001bU
#define GF_TM0	     92
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x0124U

#elif GF_M == 1264

#define GF_L	     16
#define GF_K	     79
#define GF_T	      9
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0805U

#elif GF_M == 1335

#define GF_L	     15
#define GF_K	     89
#define GF_T	     38
#define GF_RP	0x0003U
#define GF_TM0	     52
#define GF_TM1	0x0001U
#define GF_TM2	0x0001U
#define EC_B	0x06cfU

#elif GF_M == 1339

#define GF_L	     13
#define GF_K	    103
#define GF_T	      9
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0008U

#elif GF_M == 1358

#define GF_L	     14
#define GF_K	     97
#define GF_T	      6
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	     92
#define GF_TM1	0x2a00U
#define GF_TM2	0x2a00U
#define EC_B	0x0338U

#elif GF_M == 1424

#define GF_L	     16
#define GF_K	     89
#define GF_T	     38
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	     52
#define GF_TM1	0x2800U
#define GF_TM2	0x2800U
#define EC_B	0x0829U

#elif GF_M == 1455

#define GF_L	     15
#define GF_K	     97
#define GF_T	      6
#define GF_RP	0x0003U
#define GF_TM0	     92
#define GF_TM1	0x0001U
#define GF_TM2	0x0001U
#define EC_B	0x01a7U

#elif GF_M == 1469

#define GF_L	     13
#define GF_K	    113
#define GF_T	      9
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x00a3U

#elif GF_M == 1507

#define GF_L	     11
#define GF_K	    137
#define GF_T	     21
#define GF_RP	0x0005U
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0120U

#elif GF_M == 1510

#define GF_L	     10
#define GF_K	    151
#define GF_T	      3
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x0002U

#elif GF_M == 1528

#define GF_L	      8
#define GF_K	    191
#define GF_T	      9
#define GF_RP	0x001dU
#define GF_NZT	0x0020U
#define GF_TM0	      1
#define GF_TM1	0x0020U
#define EC_B	0x001fU

#elif GF_M == 1545

#define GF_L	     15
#define GF_K	    103
#define GF_T	      9
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x00ccU

#elif GF_M == 1552

#define GF_L	     16
#define GF_K	     97
#define GF_T	      6
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	     92
#define GF_TM1	0x2800U
#define GF_TM2	0x2800U
#define EC_B	0x001aU

#elif GF_M == 1582

#define GF_L	     14
#define GF_K	    113
#define GF_T	      9
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x001fU

#elif GF_M == 1648

#define GF_L	     16
#define GF_K	    103
#define GF_T	      9
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0b56U

#elif GF_M == 1651

#define GF_L	     13
#define GF_K	    127
#define GF_T	      1
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x0160U

#elif GF_M == 1695

#define GF_L	     15
#define GF_K	    113
#define GF_T	      9
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x01b4U

#elif GF_M == 1737

#define GF_L	      9
#define GF_K	    193
#define GF_T	     15
#define GF_RP	0x0011U
#define GF_TM0	      1
#define GF_TM1	0x0021U
#define EC_B	0x0016U

#elif GF_M == 1778

#define GF_L	     14
#define GF_K	    127
#define GF_T	      1
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x0027U

#elif GF_M == 1781

#define GF_L	     13
#define GF_K	    137
#define GF_T	     21
#define GF_RP	0x001bU
#define GF_TM0	      1
#define GF_TM1	0x0201U
#define EC_B	0x000cU

#elif GF_M == 1808

#define GF_L	     16
#define GF_K	    113
#define GF_T	      9
#define GF_RP	0x002dU
#define GF_NZT	0x0800U
#define GF_TM0	      1
#define GF_TM1	0x2800U
#define EC_B	0x0087U

#elif GF_M == 1837

#define GF_L	     11
#define GF_K	    167
#define GF_T	      6
#define GF_RP	0x0005U
#define GF_TM0	    162
#define GF_TM1	0x0201U
#define GF_TM2	0x0201U
#define EC_B	0x0021U

#elif GF_M == 1905

#define GF_L	     15
#define GF_K	    127
#define GF_T	      1
#define GF_RP	0x0003U
#define GF_TM0	      1
#define GF_TM1	0x0001U
#define EC_B	0x00aeU

#elif GF_M == 1910

#define GF_L	     10
#define GF_K	    191
#define GF_T	      9
#define GF_RP	0x0009U
#define GF_NZT	0x0080U
#define GF_TM0	      1
#define GF_TM1	0x0080U
#define EC_B	0x0082U

#elif GF_M == 1918

#define GF_L	     14
#define GF_K	    137
#define GF_T	     21
#define GF_RP	0x002bU
#define GF_NZT	0x0200U
#define GF_TM0	      1
#define GF_TM1	0x2a00U
#define EC_B	0x002dU

#else

#error "The selected GF_M value is not acceptable"

#endif /* GF_M */
