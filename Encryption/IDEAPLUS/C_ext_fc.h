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
 * File Name:           c_ext_fc.h
 *
 * Compile Option:      __STDC__:  if defined, ANSI C source code is generated,
 *                                 else, Kernighan & Ritchie C source code.
 *                                 Note: often compilers defined it.
 *
 * Description:
 *      The macros defined below allow the prototype of the routines to be
 *      compliant either to ANSI C format or to Kernighan & Ritchie C format.
 *
 *      Examples:
 *
 *      type_t function C_EXT_ARG(( type_t mat, int i, int j));
 *      will be transformed by the pre-processor:
 *        type_t function ( type_t mat, int i, int j );         __STDC__
 *        type_t function ();                                   !__STDC__
 *
 *      type_t function C_EXT_NOARG;
 *      will be transformed by the pre-processor:
 *        type_t function (void);                               __STDC__
 *        type_t function ();                                   !__STDC__
 */

#ifndef _c_ext_fc_h_
#define _c_ext_fc_h_

#ifdef __STDC__         /* ANSI C */
#define _VOID_                                  void
#define C_EXT_ARG(args)                         args

#else                   /* Kernighan & Ritchie C */
#define _VOID_
#define C_EXT_ARG(args)                         ()

#endif /* __STDC__ */
#endif /* !_c_ext_fc_h_ */
