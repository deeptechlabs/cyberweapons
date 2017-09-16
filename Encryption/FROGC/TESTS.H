/*

FILENAME:  tests.h

AES Submission: FROG

Principal Submitter: TecApro

*/

void MonteCarloTestCBCDecrypt (char *filename);
void MonteCarloTestCBCEncrypt (char *filename);
void MonteCarloTestECB (char *filename, BYTE direction);
void VariableKeyKAT (char *filename);
void VariableTextKAT (char *filename);

void openFile (char *filename);
void closeFile ();
void outputLineFeed ();
void outputInteger (char *format, int i);
void outputBinary (char *Item, BYTE *value, int Size);
void outputString (char *Item);
void outputHeader (char *filename, char *title, char *title2);

