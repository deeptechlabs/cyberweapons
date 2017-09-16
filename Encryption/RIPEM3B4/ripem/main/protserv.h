/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- protserv.h -- Definitions for the protocol used to talk to the
 *	key server.
 */


#define CMD_UNDEF   	0
#define CMD_LOOKUSER 1
#define CMD_ADDUSER  2
#define CMD_REPUSER  3
#define CMD_DELUSER  4
#define CMD_QUIT     5

#define CMD_LOOKUSER_TXT	"LOOKUSER"
#define CMD_ADDUSER_TXT 	"ADDUSER"
#define CMD_REPUSER_TXT		"REPUSER"
#define CMD_DELUSER_TXT		"DELUSER"
#define CMD_QUIT_TXT			"QUIT" 

#define RESP_UNDEF   	0
#define RESP_USERINFO   1
#define RESP_REDIRECT   2
#define RESP_NOTFOUND   3
#define RESP_BADFMT     4

#define RESP_USERINFO_TXT	"USERINFO"
#define RESP_REDIRECT_TXT	"REDIRECT"
#define RESP_NOTFOUND_TXT	"NOTFOUND"
#define RESP_BADFMT_TXT		"BADFMT"

#define SERVER_FIELD			"Server:"

struct struct_cmd {
  char *cmd_txt;
  int   cmd_len;
  int   cmd_id;
};

#ifdef MAIN

#define gen_cmd(ent) CMD_##ent##_TXT,(sizeof CMD_##ent##_TXT) - 1,CMD_##ent

struct struct_cmd Commands[] = {
  gen_cmd(LOOKUSER), gen_cmd(ADDUSER),  gen_cmd(REPUSER),  gen_cmd(DELUSER),
  gen_cmd(QUIT),
  NULL      ,0,0
};

#define gen_resp(ent) RESP_##ent##_TXT,sizeof RESP_##ent##_TXT - 1,RESP_##ent

struct struct_cmd Responses[] = {
  gen_resp(USERINFO), gen_resp(REDIRECT), gen_resp(NOTFOUND),
  gen_resp(BADFMT),
  NULL      ,0,0
};
#endif

