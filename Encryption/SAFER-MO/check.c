/*******************************************************************************
*
* FILE:           check.c
*
* DESCRIPTION:    checks the correctness of user-command 'safer'
*
* AUTHOR:         Richard De Moliner (demoliner@isi.ee.ethz.ch)
*                 Signal and Information Processing Laboratory
*                 Swiss Federal Institute of Technology
*                 CH-8092 Zuerich, Switzerland
*
* DATE:           September 9, 1995
*
* CHANGE HISTORY:
*
*******************************************************************************/

/******************* External Headers *****************************************/
#include <stdio.h>
#include <stdlib.h>

/******************* Constants ************************************************/
#define IN_FILE_NAME     "check.in"
#define OUT_FILE_NAME    "check.out"
#define TMP_FILE_NAME    "check.tmp"
#define REF_FILE_NAME    "check.ref"

#define COMMAND_NAME_LEN     80
#define COMMAND_LIST_LEN     17

#ifndef TRUE
#define TRUE                  1 /* boolean constant for true                  */
#endif
#ifndef FALSE
#define FALSE                 0 /* boolean constant for false                 */
#endif

/******************* Macros ***************************************************/

/******************* Types ****************************************************/

/******************* Module Data **********************************************/
static int ok;
static struct command_list_t
{
    int result_is_binary;
    char name[COMMAND_NAME_LEN];
}
command_list[COMMAND_LIST_LEN] =
{
    { TRUE, "safer -e -ecb -kx 0000000000000000 -r 6" },
    { TRUE, "safer -e -ecb -kx 0102030405060708 -r 6" },
    { TRUE, "safer -e -ecb -kx 0807060504030201 -r 6" },
    { TRUE, "safer -e -ecb -kx 08070605040302010807060504030201 -r 12" },
    { TRUE, "safer -e -ecb -kx 01020304050607080807060504030201 -r 12" },
    { TRUE, "safer -e -ecb -kx 0000000000000001 -s -r 6" },
    { TRUE, "safer -e -ecb -kx 0102030405060708 -s -r 6" },
    { TRUE, "safer -e -ecb -kx 00000000000000010000000000000001 -s -r 10" },
    { TRUE, "safer -e -ecb -kx 01020304050607080000000000000000 -s -r 10" },
    { TRUE, "safer -e -ecb -kx 00000000000000000102030405060708 -s -r 10" },
    { TRUE, "safer -e -ecb -k AaBcDeFgHiJkLmNoPqRsTuVwXyZz0123456789" },
    { TRUE, "safer -ecbkx 42431BA40D291F81D66083C605D3A4D6" },
    { TRUE, "safer -cbckx 42431BA40D291F81D66083C605D3A4D6:74536EBDC211484A" },
    { TRUE, "safer -cfbkx 42431BA40D291F81D66083C605D3A4D6:74536EBDC211484A" },
    { TRUE, "safer -ofbkx 42431BA40D291F81D66083C605D3A4D6:74536EBDC211484A" },
    { FALSE, "safer -h -tan -kx 42431BA40D291F81D66083C605D3A4D6" },
    { FALSE, "safer -h -abr -kx 42431BA40D291F81D66083C605D3A4D6" }
};

/******************* Functions ************************************************/

/******************************************************************************/
#ifndef NOT_ANSI_C
    static void Create_In_File(void)
#else
    static Create_In_File()
#endif

{   unsigned char ch;
    FILE *in_file;
    int i, k;

    if (!ok) return;
    printf("- creating binary file '%s'...\n", IN_FILE_NAME);
    if ((in_file = fopen(IN_FILE_NAME, "wb")) == NULL)
    {
        fprintf(stderr, "*** could not create file '%s'\n", IN_FILE_NAME);
        ok = FALSE;
        return;
    }
    for (k = 0; k < 2; k++)
    {
        ch = '\000';
        for (i = 0; i < 8; i++)
            fwrite(&ch, sizeof(unsigned char), 1, in_file);
        for (ch = '\001'; ch <= '\010'; ch++)
            fwrite(&ch, sizeof(unsigned char), 1, in_file);
    }
    for (i = 0; i < 256; i++)
    {
        ch = (unsigned char)(i);
        fwrite(&ch, sizeof(unsigned char), 1, in_file);
    }
    fclose(in_file);
} /* Create_In_File */

/******************************************************************************/
#ifndef NOT_ANSI_C
    static void Dump_File(char in_file_name[], int as_binary, FILE *out_file)
#else
    static Dump_File(in_file_name, as_binary, out_file)
    char in_file_name[];
    int as_binary;
    FILE *out_file;
#endif

{   FILE *in_file;
    char ch;
    int k;

    if (!ok) return;
    if (as_binary)
        in_file = fopen(in_file_name, "rb");
    else
        in_file = fopen(in_file_name, "r");
    if (in_file == NULL)
    {
        fprintf(stderr, "*** could not open file \"%s\"\n", in_file_name);
        ok = FALSE;
        return;
    }
    if (!as_binary)
        fprintf(out_file, "\n");
    for (k = 0; fread(&ch, sizeof(char), 1, in_file) == 1; k++)
        if (as_binary)
        {
            if (k % 16 == 0) fprintf(out_file, "\n ");
            else if (k % 8 == 0) fprintf(out_file, "  ");
            fprintf(out_file, " %3u", (unsigned int)(unsigned char)ch);
        }
        else
            fprintf(out_file, "%c", ch);
    if (as_binary)
        fprintf(out_file, "\n");
    fclose(in_file);
} /* Dump_File */

/******************************************************************************/
#ifndef NOT_ANSI_C
    static void Create_Out_File(void)
#else
    static Create_Out_File()
#endif

{   FILE *out_file;
    char command[2 * COMMAND_NAME_LEN];
    int i;

    if (!ok) return;
    printf("- creating text file '%s'...\n", OUT_FILE_NAME);
    if ((out_file = fopen(OUT_FILE_NAME, "w")) == NULL)
    {
        fprintf(stderr, "*** could not create file '%s'\n", OUT_FILE_NAME);
        ok = FALSE;
        return;
    }
    fprintf(out_file, "Examples of Encrypted Data using SAFER\n");
    fprintf(out_file, "======================================\n");
    fprintf(out_file, "\ninput data\n");
    Dump_File(IN_FILE_NAME, TRUE, out_file);
    for (i = 0; ok && i < COMMAND_LIST_LEN; i++)
    {
        sprintf(command, "%s %s %s",
                command_list[i].name, IN_FILE_NAME, TMP_FILE_NAME);
        system(command);
        fprintf(out_file, "\n%s\n", command_list[i].name);
        Dump_File(TMP_FILE_NAME, command_list[i].result_is_binary, out_file);
    }
    fprintf(out_file, "\n");
    fclose(out_file);
} /* Create_Out_File */

/******************************************************************************/
#ifndef NOT_ANSI_C
    static void Compare_Out_File_With_Ref_File(void)
#else
    static Compare_Out_File_With_Ref_File()
#endif

{   FILE *fd_1, *fd_2;
    char ch_1, ch_2;
    int equal;

    if (!ok) return;
    printf("- comparing text files '%s' and '%s' ...\n",
           OUT_FILE_NAME, REF_FILE_NAME);
    if ((fd_1 = fopen(OUT_FILE_NAME, "r")) == NULL)
    {
        fprintf(stderr, "*** could not open file '%s'\n", OUT_FILE_NAME);
        ok = FALSE;
        return;
    }
    if ((fd_2 = fopen(REF_FILE_NAME, "r")) == NULL)
    {
        fprintf(stderr, "*** could not open file '%s'\n", REF_FILE_NAME);
        ok = FALSE;
        return;
    }
    equal = TRUE;
    if ('\0' < (ch_1 = fgetc(fd_1)) && ch_1 < ' ') ch_1 = '\n';
    if ('\0' < (ch_2 = fgetc(fd_2)) && ch_2 < ' ') ch_2 = '\n';
    while (ch_1 != EOF && ch_2 != EOF)
    {
        equal = equal && ch_1 == ch_2;

        if (ch_1 == '\n')
            while ('\0' < (ch_1 = fgetc(fd_1)) && ch_1 < ' ');
        else if ('\0' < (ch_1 = fgetc(fd_1)) && ch_1 < ' ')
            ch_1 = '\n';

        if (ch_2 == '\n')
            while ('\0' < (ch_2 = fgetc(fd_2)) && ch_2 < ' ');
        else if ('\0' < (ch_2 = fgetc(fd_2)) && ch_2 < ' ')
            ch_2 = '\n';
    }
    fclose(fd_1);
    fclose(fd_2);
    if (equal && ch_1 == ch_2)
        printf("  files are equal, test completed successfully\n");
    else
        printf("  *** error: files are not equal!!!\n");
} /* Compare_Out_File_With_Ref_File */

/*******************************************************************************
*                                    M A I N
*******************************************************************************/
#ifndef NOT_ANSI_C
    int main(void)
#else
    int main()
#endif

{   ok = TRUE;
    Create_In_File();
    Create_Out_File();
    Compare_Out_File_With_Ref_File();
    return ok != TRUE;
} /* main */

/******************************************************************************/
