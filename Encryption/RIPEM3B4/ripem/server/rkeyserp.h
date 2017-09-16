#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* rkeyserv.c */
int main P((int argc , char *argv []));
int ProcessRequest P((int sock , char *buf , int receivedBytes , struct sockaddr_in *fromSockName ));
int WhichCommand P((char *cmd ));
int GetUserPubInfo P((char *user , char *userInfo , int maxInfoLen ));
int GetKeyField P((char *field , char *userInfo , char *line , int maxLineLen ));
int SendReply P((int sock , struct sockaddr_in *sockName , char *buf , int bufLen ));
int SendReplyStr P((int sock , struct sockaddr_in *sockName , char *buf ));
void GetMyIPAddress P((struct in_addr *MyIPAddress ));
void SigHandler P((int signo ));

#undef P
