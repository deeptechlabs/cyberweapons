/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/* Put usage_msg_line1 in a separate buffer so that main can append the
     RIPEM_VERSION string.
 */
char usage_msg_line1[80] = 
#ifdef RIPEMSIG
 "ripemsig: {Riordan's|RSAREF-based} Internet Privacy Enhanced Mail, v ";
#else
 "ripem: {Riordan's | RSAREF-based} Internet Privacy Enhanced Mail, v ";
#endif

char *usage_msg[] = {
#ifdef RIPEMSIG
 usage_msg_line1,
 "*** Exportable signature-only version ***",
 "Signs/verifies mail messages using RSA and MD5, and generates keys.",
#else
 usage_msg_line1,
 "Encrypts/decrypts mail messages using RSA and DES/RX2, and generates keys.",
#endif
 "ripem is in the public domain, but requires agreeing to the RSAREF license ",
 "from RSA Data Security; contact rsaref-info@rsa.com.  It's free but limited.",
 "By Mark Riordan (mrr@ripem.msu.edu), Jeff Thompson & others.",
 "Usage:  ripem {-e | -d | -g | -G | -c}     <in >out",
#ifdef RIPEMSIG
 "  [-r recipient] [-m {mic-only | mic-clear}]",
#else
 "  [-r recipient] [-m {encrypted | mic-only | mic-clear | enveloped-only}]",
#endif
 "  [-M message_format] [-u myusername] [-h head] [-b #_bits_in_gen_key] [-B]",
 "  [-p publickey_infile(s)] [-s privatekey_infile] [-k key_to_private_key or -]",
 "  [-A enc_alg] [-y pub_key_server_name] [-Y key_sources] [-T recip_opts]",
 "  [-i infile] [-o outfile] [-D debug_level] [-Z debug_out_file]          ",
 "  [-R random_sources] [-F random_input_file] [-C random_string]         ",
 "  [-v #_of_validity_months] [-K new_key_to_private_key] [-H home_dir]   ",
 "  [-x external_msg_file]  [-a dig_alg]",
 "where:",
 "  message_format is: ripem1 (default),pem or pkcs. Can use -M pkcs to -d PKCS",
 "  enc_alg is the encryption alg: des-cbc (def), des-ede-cbc or rx2-cbc/bits.",
 "  external_msg_file is the message file for detached signature (-M pkcs only).",
 "  dig_alg is digest alg.(-d -M pkcs -x only): rsa-md5 (deflt), rsa-md2, sha-1",
 "  key_sources is a string of one or more of \"fgs\", which tell ripem to look",
 "    for public keys from a File, finGer, or Server, in the order specified.",
 "  head is one or more of \"ipr\", for Include headers in msg; Prepend headers",
 "    to output; get Recipients from headers.  ",
 "  random_sources is one or more of \"cefkms\", specifying \"random\" input from",
 "    Command line, Entire command, File, Keyboard, Message, or running System.",
 "  recip_opts is one or more of \"amn\", for Abort if can't find keys for all",
 "    users;include Me as a recipient if encrypting(default); None of the above.",
 "Relevant environment variables:   RIPEM_HOME_DIR,",
 "  RIPEM_PUBLIC_KEY_FILE, RIPEM_PRIVATE_KEY_FILE, RIPEM_KEY_TO_PRIVATE_KEY,",
 "  RIPEM_USER_NAME, RIPEM_RANDOM_FILE, RIPEM_SERVER_NAME, RIPEM_ARGS",
(char *)0
};
