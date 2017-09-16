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
/*   Release:   2.1                                                          */
/*                                                                           */
/*****************************************************************************/
/*
 * File Name:		ideaplus.h
 *
 * Compile Options:	- none
 *
 * Description:
 *	Header file for the IDEA 64-bit block encryption algorithm.
 *	The types uint16, uint32, and int32, should be defined to comply with
 *	the optimum size of the compiler.
 *
 *	Examples:
 *
 *	Sun SPARCS -	typedef unsigned short uint16;
 *			typedef unsigned int uint32;
 *			typedef int int32;
 *
 *	VAX -		typedef unsigned short uint16;
 *			typedef unsigned int uint32;
 *			typedef int int32;
 *
 *	PC -		typedef unsigned int uint16;
 *			typedef unsigned long uint32;
 *			typedef long int32;
 */

#ifndef _ideaplus_h_
#define _ideaplus_h_

#include "c_ext_fc.h"

typedef unsigned short 	uint16;			/* 16-bit word */
typedef unsigned long	uint32;			/* 32-bit word */
typedef long		int32;			/* 32-bit int */

#define IDEA_ROUNDS 8				/* Number of IDEA rounds  */
#define IDEA_SK_NUM (6 * IDEA_ROUNDS + 4)	/* Number of IDEA subkeys */

typedef uint16 idea_block_t[4];			/* in/output IDEA data block */
typedef uint16 idea_key_t[8];			/* local key type */
typedef uint16 idea_subkeys_t[IDEA_SK_NUM];	/* local IDEA subkeys type */

extern _VOID_ idea_encrypt_subkeys C_EXT_ARG((idea_key_t,idea_subkeys_t));
extern _VOID_ idea_decrypt_subkeys C_EXT_ARG((idea_subkeys_t,idea_subkeys_t));
extern _VOID_ idea_cipher C_EXT_ARG((idea_block_t,idea_block_t,idea_subkeys_t));

#endif /* !_ideaplus_h_ */
