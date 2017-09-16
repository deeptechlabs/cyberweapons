/*
 * Secure packet radio login command. The system first prompts for the
 * user's name. It then generates and sends a unique "challenge" (a 64-bit
 * hexadecimal integer) based on the time of day. The user encrypts
 * this value using the Data Encryption Standard and his private key and
 * type it back to the system. The system also encrypts the challenge
 * with the user's key and compares the two. If they match, he's in.
 *
 * 18 December 1986 Phil Karn, KA9Q
 *
 * mods:
 *   870318 Bdale, N3EUA     Add code to run user's .login commands.
 *   870317 Bdale, N3EUA     Hacked to remove putenv() by calling execle()
 *                           instead of execl().
 */
#include <stdio.h>
#include <strings.h>
#include <pwd.h>
#include <utmp.h>
#define	KEYFILE	"/etc/rkeys"	/* This file must be read-protected */
main(argc,argv)
int argc;
char *argv[];
{
	struct passwd *pp,*getpwnam();
	unsigned long t;
	FILE *fp;
	char name[64];
	char key[8];
	char work[8];
	char answer[8];
	char fbuf[64];
	char ibuf[64];
	char home[64];
	char login[64];
	char shell[64];
	char user[64];
	char *keyp;
	char *cp,*tty,*ttyname();
	int i,ikey[8];
	struct utmp utmp;
	char *ep[5];               /* we'll build an environment here */

	if((fp = fopen(KEYFILE,"r")) == NULL){
		printf("Can't open key file\n");
		exit(1);
	}
	/* Get user's name and look it up in the database */
	printf("Enter login name: ");
	fgets(ibuf,sizeof(ibuf),stdin);
	if((cp = index(ibuf,'\n')) != NULL)
		*cp = '\0';
	strncpy(name,ibuf,sizeof(name));
	for(;;){
		fgets(fbuf,sizeof(fbuf),fp);
		if(feof(fp)){
			printf("No key for login name\n");
			exit(2);
		}
		if((cp = index(fbuf,'\n')) != NULL)
			*cp = '\0';
		if(strncmp(name,fbuf,strlen(name)) == 0)
			break;
	}
	fclose(fp);
	/* Find the user's DES key */
	if((keyp = index(fbuf,' ')) == NULL){
		printf("Missing key field\n");
		exit(3);
	}
	keyp++;
	/* Initialize DES with the user's key */
	sscanf(keyp,"%2x%2x%2x%2x%2x%2x%2x%2x",
	 &ikey[0], &ikey[1], &ikey[2], &ikey[3], &ikey[4], &ikey[5],
	 &ikey[6], &ikey[7]);

	for(i=0;i<8;i++)
		key[i] = ikey[i];

	desinit(0);
	setkey(key);

	/* Generate and send the challenge */
	time(&t);
	printf("Challenge: %016x\n",t);

	/* Encrypt it locally... */
	for(i=0;i<4;i++)
		work[i] = 0;
	work[4] = t >> 24;
	work[5] = t >> 16;
	work[6] = t >> 8;
	work[7] = t;
	endes(work);
	
	/* ...and see if the user can do the same */
	printf("Response:  ");
	for(i=0;i<8;i++){
		scanf("%2x",&t);
		answer[i] = t;
	}
	printf("\n");     /* I like it better with a blank line here - bdale */
	/* Compare the ciphertexts. If they match, he's in */
	for(i=0; i < 8; i++){
		if(work[i] != answer[i]){
			printf("Wrong response\n");
			exit(4);
		}
	}
	if((pp = getpwnam(name)) == NULL){
		printf("login name \"%s\" not in /etc/passwd\n",name);
		exit(4);
	}
	if((fp = fopen(UTMP_FILE,"r+")) == NULL){
		printf("can't open utmp\n");
		exit(4);
	}
	tty = ttyname(0);
	if((cp = rindex(tty,'/')) != NULL)
		tty = cp + 1;
	while(fread((char *)&utmp,sizeof(struct utmp),1,fp),!feof(fp)){
		if(strncmp(utmp.ut_line,tty,8) == 0){
			strncpy(utmp.ut_name,name,8);
			fseek(fp,(long)-sizeof(struct utmp),1);
			fwrite((char *)&utmp,sizeof(struct utmp),1,fp);
			break;
		}
	}
	fclose(fp);
	chdir(pp->pw_dir);
	setregid(pp->pw_gid,pp->pw_gid);
	setreuid(pp->pw_uid,pp->pw_uid);
	if(pp->pw_shell == NULL || *pp->pw_shell == '\0')
		pp->pw_shell = "/bin/ksh";
	sprintf(home,"HOME=%s",pp->pw_dir);
	sprintf(shell,"SHELL=%s",pp->pw_shell);
	sprintf(user,"USER=%s",name);
	sprintf(login,"%s/.login",pp->pw_dir);
	ep[0] = home;
	ep[1] = shell;
	ep[2] = user;
	ep[3] = (char *) NULL;
	execle(pp->pw_shell,"-",0,ep);
	printf("Exec failed\n");
}
