/*****************************************************************************/
/*                        IDEA Encryption Algorithm                          */
/*****************************************************************************/
/*                                                                           */
/*   IDEA (International Data Encryption Algorithm) is a block encryption    */
/*   algorithm whose development results from a co-operation between the     */
/*   Swiss Federal Institute of Technology Zurich (ETHZ) and Ascom Tech Ltd. */
/*   IDEA encrypts or decrypts 64-bit data blocks, using symmetric 128-bit   */
/*   keys. The 128-bit keys are furthermore expanded to 52 16-bit subkeys.   */
/*                                                                           */
/*   For detailed technical information on IDEA contact:                     */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*   Patent rights of Ascom Systec Ltd. granted in Europe, Japan and the US. */
/*   All other rights reserved.                                              */
/*                                                                           */
/*   For detailed patent information on IDEA contact:                        */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*   Author:    Alain Beuchat/Daniel Zimmermann                              */
/*   Release:   2.0                                                          */
/*                                                                           */
/*****************************************************************************/
/*
 * File Name:		c_fct.h
 *
 * Compile Option:	__STDC__:  if defined, ANSI C source code is generated,
 *				   else, Kernighan & Ritchie C source code.
 *				   Note: often compilers defined it.
 *
 * Description:
 *	The macros defined below allow the routine declarations to be defined
 *	either under ANSI C format or under Kernighan & Ritchie C format.
 *
 *	Example:
 *	type_t function C_ARG_2( type_t,mat, int,i)
 *	will be transformed by the pre-processor:
 *	  type_t function ( type_t mat, int i );		__STDC__
 *	  type_t function ( mat, i ); type_t mat; int i;	!__STDC__
 */

#ifndef _c_fct_h_
#define _c_fct_h_

#ifdef __STDC__		/* ANSI C */
#define C_ARG_1(a1t,a1n)			(a1t a1n)
#define C_ARG_2(a1t,a1n,a2t,a2n)		(a1t a1n,a2t a2n)
#define C_ARG_3(a1t,a1n,a2t,a2n,a3t,a3n)	(a1t a1n,a2t a2n,a3t a3n)

#else			/* Kernighan & Ritchie C */
#define C_ARG_1(a1t,a1n)			(a1n) a1t a1n;
#define C_ARG_2(a1t,a1n,a2t,a2n)		(a1n,a2n) a1t a1n; a2t a2n;
#define C_ARG_3(a1t,a1n,a2t,a2n,a3t,a3n)	(a1n,a2n,a3n) a1t a1n; a2t a2n;\
							      a3t a3n;
#endif /* __STDC__ */
#endif /* !_c_fct_h_ */
