/* Preprocessor file to convert generic AT&T assembler syntax code to OS-
   specific variants, based on a version by Eric Young.

   Sent to me by Peter Gutmann. I have added CSymbol to support external 
   variables. -Leonard Janke */

#ifndef _ASM_H
#define _ASM_H

#if !( defined( OUT ) || defined( BSDI ) || defined( ELF ) || defined( SOLARIS ) )
  #error You need to define one of OUT, BSDI, ELF, or SOLARIS
#endif /* Check for missing defines */

#define TYPE( a, b )	.type a, b
#define SIZE( a, b )	.size a, b

/* a.out (older Linux, FreeBSD).  Underscores on names, align to word
   boundaries */

#ifdef OUT
  #define FUNCTION( name )	_name
  #define CSYMBOL( name )	_name
  #define ALIGN				4
#endif /* OUT */

/* BSDI.  As a.out, but with an archaic version of as */

#ifdef BSDI
  #define FUNCTION( name )	_name
  #define CSYMBOL( name )	_name
  #define ALIGN				4
  #undef SIZE
  #undef TYPE
#endif /* BSDI */

/* ELF (newer Linux, NetBSD, DG-UX), Solaris (as ELF but with strange comment
   lines).  No underscores on names, align to paragraph boundaries */

#if defined( ELF ) || defined( SOLARIS )
  #define FUNCTION( name )	name
  #define CSYMBOL( name )	name
  #define ALIGN				16
#endif /* ELF || SOLARIS */

#endif /* _ASM_H */
