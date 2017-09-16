/******   eliptic.h   *****/
/****************************************************************
*                                                               *
*       These are structures used to create elliptic curve      *
*  points and parameters.  "form" is a just a fast way to check *
*  if a2 == 0.                                                  *
*               form            equation                        *
*                                                               *
*                0              y^2 + xy = x^3 + a_6            *
*                1              y^2 + xy = x^3 + a_2*x^2 + a_6  *
*                                                               *
****************************************************************/

typedef struct {
        INDEX   form;
        BIGINT  a2;
        BIGINT  a6;
} CURVE;

/*  coordinates for a point  */

typedef struct {
        BIGINT  x;
        BIGINT  y;
} POINT;

/*  started getting tired of writing this */

#define SUMLOOP(i) for(i=STRTPOS; i<MAXLONG; i++)

#ifdef ANSI_MODE
void one (BIGINT * place);
int gf_quadradic (BIGINT * a, BIGINT * b, BIGINT * c);
void fofx (BIGINT * x, CURVE * curv, BIGINT * f);
void esub (POINT * p1, POINT * p2, POINT * p3, CURVE * curv);
void esum (POINT * p1, POINT * p2, POINT * p3, CURVE * curv);
void edbl (POINT * p1, POINT * p3, CURVE * curv);
void copy_point (POINT * p1, POINT * p2);
void elptic_mul(BIGINT * k, POINT * p, POINT * r, CURVE * curv);
#endif
#endif
