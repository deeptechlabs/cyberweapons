unit BfishCBC;

  {*****************************************************************}
  {*******      BLW-CBC.pas (c) 1997 by Dutra de Lacerda     *******}
  {*******   E-Mail address:  dulac@ip.pt   FIDO: 2:362/20   *******}
  {*******  Example program of the usage of the BLW_CBC Unit *******}
  {*******        Hereby donated to the public domain        *******}
  {*****************************************************************}

interface

uses BFish4b, Dos;

const
  Debug      = FALSE;
  BufferSize = 8192;
  BlockSize  = 8;
  HalfSize   = 4;
  Version    = 15;

procedure BLW_CBC_INIT(var k : String; N : Integer);
procedure BLW_CBC_CRYPT(var InputFile : String; var OutputFile : String);
procedure BLW_CBC_DECRYPT(var InputFile : String; var OutputFile : String);


implementation


var
  VersionL : LongInt; {Value in EOF Header}
  VersionC : Array[0..3] of Char ABSOLUTE VersionL;
  VersionB : Array[0..3] of Byte ABSOLUTE VersionL;
  (***********************************************************)
  (* Tail Format (extensible backwards):                     *)
  (* ~~~~~~~~~~~                                             *)
  (*    IVleft : Longint;                                    *)
  (*    IVright: Longint;                                    *)
  (*    version: byte; (compatibility)  | Both make Version? *)
  (*    Extension: Array[1..3] of char; | Arrays = 4 bytes   *)
  (*    FileSize : Longint;                                  *)
  (*    -------------------                                  *)
  (*    Total: 16 bytes (minimum size)                       *)
  (***********************************************************)

  Key : String[56];
  InputFile,
  OutputFile : PathStr;
  Argument : String[2];
  Teller,
  FillBuffer,
  NumRead,
  NumWritten : Word; { MUST be global }
  Input,             { MUST be global }
  Output : file;     { MUST be global }
  Buffer : array[0..BufferSize-1] of LongInt;
  FileVersion,
  FileOrigSize,
  InputSize,
  Counter,
  CBCinit,
  CBC_l0,
  CBC_r0,
  CBC_l,
  CBC_r,
  _CBC_l,
  _CBC_r : LongInt;
  Pad_B : Array[0..15] OF byte;
  Pad_L : Array[0..3] OF LongInt ABSOLUTE Pad_B;
  Buf : Byte absolute Buffer;
  P : PArray;
  S : SBox;
  PP : array[0..17, 0..3] of Byte absolute P;
  SS : array[0..3, 0..255, 0..3] of Byte absolute S;
  BB : array[0..(HalfSize*BufferSize)-1] of Byte absolute Buffer;
  NIteract,
  NBlocks,
  NHalfs,
  NPadBytes,
  IOerror,
  i : Integer;

  Fpath : Pathstr;
  Fdir  : DirStr;
  Fname : NameStr;
  Fext  : ExtStr;


  Procedure Create_CBC_IV( Init:LongInt; VAR Tl:LongInt; VAR Tr:LongInt );
  const
    DebugNum = $AAAAAAAA;
  var
    T    : Array[0..3] OF byte ABSOLUTE Tl;
    Regs : Registers;
  begin
    If not Debug then
       begin
       Regs.AH := $2C;
       MsDos(Regs);
       with Regs do   { The order is not significant, choosed to put the }
         begin        { most variable data alternated with the less one. }
         T[0] := CH;  { Hour   }
         T[1] := DL;  { Hundreds of second }
         T[2] := CL;  { Minute }
         T[3] := DH;  { Second }
         end;         { NOTICE that T alters T1 }
       Tl := Tl xor not DebugNum;
       Tr := Init xor DebugNum;
       end
    else
       Begin
       Tl := DebugNum;
       Tr := DebugNum;
       end;
  end;

  function CheckDisk: Boolean;
  begin
    if NumWritten=0 then
      begin
      Writeln;
      Writeln( #13, #10, 'Unable to write Disk: Check for Disk Full...' );
      close(input);
      close(output);
      halt(101);
      end;
  end;

  function CheckIO: integer;
  var IOerror : integer;
  begin
    IOError := IOresult;
    if IOError<>0 then
      begin
      ErrorAddr := NIL;
      ExitCode  := 0;
      Writeln( #13,#10, 'Please correct the problem and try again...' );
      end;
    CheckIO := IOerror;
  end;

  function Passes(InputSize : LongInt) : LongInt;
  begin
    Passes := ((InputSize div (BufferSize*4))+
               (InputSize mod (BufferSize*4))*1-
               ((InputSize mod (BufferSize*4))*1-1));
  end;

  procedure BLW_CBC_INIT(var k : String; N : Integer);
  begin
    Key := k;
    NIteract := N;
    InitBlowFish(Key, P, S);
  end;

  procedure BLW_CBC_CRYPT(var InputFile : String; var OutputFile : String);
  begin
    Assign(Input, InputFile);
    FileMode := 0; { 0= Read; 1=Write; 2=Read/Write}
    {$I-} Reset(Input, 1); {$I+} IOerror := CheckIO;
    If IOerror <> 0 then
      begin
      halt(IOerror);
      end;
    InputSize := FileSize(Input);

    Fpath := FExpand( InputFile );
    FSplit(Fpath, Fdir, Fname, Fext);

    VersionB[0] := Version;
    for i := 1 to 3 do
      if (i > ord(Fext[0])) then
        Fext[i] := #32;
    for i := 1 to 3 do
      VersionC[i] := Fext[i+1];

    if OutputFile = '' then
      OutputFile := Fname+'.BFC';
    Assign(Output, OutputFile);
    FileMode := 1; { 0= Read; 1=Write; 2=Read/Write}
    {$I-} Rewrite(Output, 1); {$I+} IOerror:=CheckIO;
    If IOerror <> 0 then
      begin
      close(input);
      halt(IOerror);
      end;

    { Initialization of the CBC Mode Initial Vector }
    GetFtime(Input, CBCinit);
    Create_CBC_IV(CBCinit, CBC_l0, CBC_r0);
    CBC_l  := CBC_l0;
    CBC_r  := CBC_r0;

    NPadBytes := 0;               {Will be used only once}
    NBlocks := BufferSize div BlockSize;
    for Counter := 1 to Passes(InputSize) do
      begin
        if Counter = Passes(InputSize) then {Last Pass}
          begin
            FillBuffer := InputSize-((Passes(InputSize)-1)*(BufferSize*4));
            NBlocks    := (FillBuffer+BlockSize-1) div BlockSize;
            NPadBytes  := BlockSize-(FillBuffer mod BlockSize);
            NHalfs     := 2*NBlocks;
          end                     {IF-else Counter...}
        else
          begin
            NHalfs := BufferSize;
          end;                    {if-Else Counter...}

        BlockRead(Input, Buffer, SizeOf(Buffer), NumRead);

        (* Padding *)
        Pad_L[0] := CBC_l0;
        Pad_L[0] := not CBC_l0;
        Pad_L[0] := CBC_r0;
        Pad_L[0] := not CBC_r0;
        if NPadBytes <> 0 then
          begin
            for i := 0 to NPadBytes-1 do
              begin
                BB[FillBuffer+i] := Pad_B[ NPadBytes - i ];
              end;                {for i...}
          end;                    {if Npad..}

        Teller := 0;
        While Teller <= (NHalfs-1) do
          begin
            Buffer[Teller]   := CBC_l xor Buffer[Teller];
            Buffer[Teller+1] := CBC_r xor Buffer[Teller+1];
            BlowEncrypt(Buffer[Teller], Buffer[Teller+1], P, S);
            CBC_l := Buffer[Teller];
            CBC_r := Buffer[Teller+1];
            Inc(Teller);
            Inc(Teller);
          end;
        BlockWrite(Output, Buffer, NumRead+NPadBytes, NumWritten);
        Write('Pass ', Counter, ' of ');
        Write((InputSize div (BufferSize*4))+1, '     ', #13);
        CheckDisk;
      end;                        {FOR}
    WriteLn;
    CBC_l := 1;
    BlockWrite(Output, CBC_l0, SizeOf(CBC_l0), NumWritten);
    CheckDisk;
    BlockWrite(Output, CBC_r0, SizeOf(CBC_r0), NumWritten);
    CheckDisk;
    BlockWrite(Output, VersionL, SizeOf(VersionL), NumWritten);
    CheckDisk;
    BlockWrite(Output, InputSize, SizeOf(InputSize), NumWritten);
    CheckDisk;
    Close(Input);
    Close(Output);
  end;



  procedure BLW_CBC_DECRYPT(var InputFile : String; var OutputFile : String);
  begin
    Assign(Input, InputFile);
    FileMode := 0; { 0= Read; 1=Write; 2=Read/Write}
    {$I-} Reset(Input, 1); {$I+} IOerror := CheckIO;
    If IOerror <> 0 then
      begin
      halt(IOerror);
      end;
    InputSize := FileSize(Input);

    Fpath := FExpand( InputFile );
    FSplit(Fpath, Fdir, Fname, Fext);

    Seek(Input, FileSize(Input)-16);
    BlockRead(Input, Buffer, SizeOf(Buffer), NumRead);
    CBC_l := Buffer[0];
    CBC_r := Buffer[1];
    VersionL  := Buffer[2];
    FileOrigSize := Buffer[3];

    if NOT (VersionB[0] = Version) then
      begin
      Write('Wrong version. File was Encrypted with version ');
      Case VersionB[0] of
        1  : WriteLn('1.3');
        15 : WriteLn('1.5');
        else
           WriteLn('???');
        end;
      halt(254);
      end;

    FileMode := 0; { 0= Read; 1=Write; 2=Read/Write}
    Reset(Input, 1);
    Fext := '.'+VersionC[1]+VersionC[2]+VersionC[3];
    if OutputFile = '' then
      OutputFile:= Fname+Fext;
    Assign(Output, OutputFile);
    FileMode := 1; { 0= Read; 1=Write; 2=Read/Write}
    {$I-} Rewrite(Output, 1); {$I+} IOerror:=CheckIO;
    If IOerror <> 0 then
      begin
      close(input);
      halt(IOerror);
      end;

    FillBuffer := BufferSize*4;
    for Counter := 1 to Passes(InputSize) do
      begin
        if Counter = Passes(InputSize) then
          begin
            FillBuffer := InputSize-((Passes(InputSize)-1)*(BufferSize*4));
          end;                    {if counter...}
        BlockRead(Input, Buffer, SizeOf(Buffer), NumRead);
        Teller := 0;
        While Teller <= ((FillBuffer div 4)-1) do
          begin
            _CBC_l := Buffer[Teller];
            _CBC_r := Buffer[Teller+1];
            BlowDecrypt(Buffer[Teller], Buffer[Teller+1], P, S);
            Buffer[Teller]   := Buffer[Teller] xor CBC_l;
            Buffer[Teller+1] := Buffer[Teller+1] xor CBC_r;
            CBC_l := _CBC_l;
            CBC_r := _CBC_r;
            Inc(Teller);
            Inc(Teller);
          end;                    {FOR}
        BlockWrite(Output, Buffer, NumRead, NumWritten);
        Write('Pass ', Counter, ' of ');
        Write((InputSize div (BufferSize*4))+1, '     ', #13);
        CheckDisk;
      end;                        {FOR}
    WriteLn;
    Seek(Output, FileOrigSize);
    Truncate(Output);
    Close(Input);
    Close(Output);
  end;

begin
end.
