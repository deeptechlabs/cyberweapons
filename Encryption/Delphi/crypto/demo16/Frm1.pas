unit Frm1;

interface

uses WinTypes, WinProcs, Classes, Graphics, Forms, Controls, Buttons,
  StdCtrls, MD5Unit, ExtCtrls, SysUtils, Dialogs,
  BlowUnit, Cryptcon, IdeaUnit, RC5Unit, mmsystem, RC4Unit, DESUnit2;

type
  Tcryptfrm = class(TForm)
    OKBtn: TBitBtn;
    Bevel1: TBevel;
    Edit1: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    OpenDialog1: TOpenDialog;
    Bevel2: TBevel;
    Edit2: TEdit;
    Label3: TLabel;
    Label4: TLabel;
    BFButton: TBitBtn;
    DeButton: TBitBtn;
    Label5: TLabel;
    Label6: TLabel;
    EnIDEAButton: TBitBtn;
    DeIdeaButton: TBitBtn;
    AlgorithmGroup: TRadioGroup;
    TimePanel: TPanel;
    Label7: TLabel;
    CipherModeGroup: TRadioGroup;
    Label9: TLabel;
    IVectorEdit: TEdit;
    procedure OKBtnClick(Sender: TObject);
    procedure BFButtonClick(Sender: TObject);
    procedure DeButtonClick(Sender: TObject);
    procedure EnIDEAButtonClick(Sender: TObject);
    procedure DeIdeaButtonClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  cryptfrm: Tcryptfrm;
  boutarray: array[0..31] of char;
  gIV: String;
implementation
 procedure md5_calc(outStr: PChar; inStr: PChar; inlen: WORD);
                   far; external 'MD5';
{$R *.DFM}

procedure Tcryptfrm.OKBtnClick(Sender: TObject);
var
 inStr, OutStr: PChar;
 md5hash: TMD5;
 outblock: hashDigest;
 outarray: array[0..15] of char absolute outblock;
begin
 inStr := Stralloc(128);
 OutStr := stralloc(16);
 md5hash:= TMD5.Create(Self);
 try
  StrPCopy(inStr, Edit1.Text);
  md5_calc(OutStr, inStr, Length(Edit1.Text));
  {test output against known output from C DLL}
  Label1.Caption := StrPas(OutStr);
  {md5hash.InputLength := Length(Edit1.Text);}
  {md5hash.pInputArray := Pointer(inStr);}
  md5hash.InputType := SourceString;
  md5hash.InputString := Edit1.Text;
  md5hash.pOutputArray := @outblock;
  md5hash.MD5_Hash;
  Label2.Caption := StrPas(outarray);

 finally
  md5hash.free;
  StrDispose(inStr);
  StrDispose(OutStr);
 end;{Finally}
end;


procedure Tcryptfrm.BFButtonClick(Sender: TObject);
var
 BlowFish1: TBlowFish;
 inStr: PChar;
 startTime: LongInt;
begin
 inStr := Stralloc(128);
 BlowFish1 := TBlowFish.Create(Self);
 try
  StrPCopy(inStr, Edit2.Text);
  BlowFish1.Key := 'abcdefghijklmnopqrstuvwxyz';

  {BlowFish.InputLength := Length(Edit2.Text);}
  {BlowFish.pInputArray := Pointer(inStr);}
  BlowFish1.InputString := Edit2.Text;
  BlowFish1.InputType := SourceString;
  BlowFish1.pOutputArray := @boutarray;
  BlowFish1.EncipherData(False);
  Label3.Caption := StrPas(boutarray);

 finally
  BlowFish1.free;
  StrDispose(inStr);
 end;{Finally}
end;


procedure Tcryptfrm.DeButtonClick(Sender: TObject);
var
 BlowFish1: TBlowFish;
 inStr: PChar;

begin
 inStr := Stralloc(128);
 {FillChar(inStr, 16, #0);}
 inStr := 'BlahBlah';
 BlowFish1 := TBlowFish.Create(Self);
 try
  StrPCopy(inStr, Edit2.Text);
  BlowFish1.Key := 'abcdefghijklmnopqrstuvwxyz';
  BlowFish1.InputLength := 8;
  BlowFish1.pInputArray := @boutarray;
  BlowFish1.InputType := SourceByteArray;
  BlowFish1.pOutputArray := Pointer(inStr);
  BlowFish1.DecipherData(False);
  Label4.Caption := StrPas(inStr);

 finally
  BlowFish1.free;
  StrDispose(inStr);
 end;{Finally}

end;

procedure Tcryptfrm.EnIDEAButtonClick(Sender: TObject);
var
 IDEA: TIDEA;
 md5hash: TMD5;
 Blowfish: TBLOWFISH;
 RC5: TRC5;
 RC4: TRC4;
 DES: TDES;
 startTime: LongInt;
 encytObject : TCrypto;
 outarray: array[0..15] of char;
begin
IDEA := TIDEA.Create(Self);
md5hash := TMD5.Create(Self);
Blowfish := TBLOWFISH.Create(Self);
RC5 := TRC5.Create(Self);
RC4 := TRC4.Create(Self);
DES := TDES.Create(Self);
 try
  If OpenDialog1.Execute then
  begin
  Screen.Cursor := crHourglass;
  case AlgorithmGroup.ItemIndex of
   0:
   begin
    md5hash.InputType := SourceFile;
    md5hash.InputFilePath := OpenDialog1.FileName;
    md5hash.pOutputArray := @outarray;
    startTime := timeGetTime;
    md5hash.MD5_Hash;
    TimePanel.Caption := IntToStr(timeGetTime - startTime);
    Label2.Caption := StrPas(outarray);
   end;
   1:
    encytObject := Blowfish;
   2:
    encytObject := IDEA;
   3:
    encytObject := RC5;
   4:
    encytObject := RC4;
   5:
    encytObject := DES;
  end;{Case}
  Screen.Cursor := crHourglass;
  Application.ProcessMessages;
  if AlgorithmGroup.ItemIndex > 0 then begin
     encytObject.Key := '1234567890123456';
     encytObject.InputType := SourceFile;
     {CipherMode is an enumerated type}
     encytObject.CipherMode := TCipherMode(CipherModeGroup.ItemIndex);
     if (encytObject.CipherMode > ECBMode) then begin
      if (Length(IVectorEdit.Text) > 7) then{most ciphers have a block size
                                           of 8, IVectors must be the same
                                           size as the BLOCK}
            encytObject.IVector := IVectorEdit.Text
      else
            encytObject.IVector := '';{Let Object Generate IVector}
     end;
     encytObject.InputFilePath := OpenDialog1.FileName;
     encytObject.OutputFilePath := ChangeFileExt(OpenDialog1.FileName, '.ccc');
     startTime := timeGetTime;
     encytObject.EncipherData(False);
     IVectorEdit.Text:= encytObject.IVector;
     TimePanel.Caption := IntToStr(timeGetTime - startTime);
  end;{if}
  end;{if}
 finally
   IDEA.free;
   md5hash.free;
   Blowfish.free;
   RC5.free;
   RC4.free;
   DES.free;
   Screen.Cursor := crDefault;
 end;
end;

procedure Tcryptfrm.DeIdeaButtonClick(Sender: TObject);
var
 IDEA: TIDEA;
 md5hash: TMD5;
 Blowfish: TBLOWFISH;
 RC5: TRC5;
 RC4: TRC4;
 DES: TDES;
 startTime: LongInt;
 encytObject : TCrypto;
 outarray: array[0..15] of char;
begin
IDEA := TIDEA.Create(Self);
md5hash := TMD5.Create(Self);
Blowfish := TBLOWFISH.Create(Self);
RC5 := TRC5.Create(Self);
RC4 := TRC4.Create(Self);
DES := TDES.Create(Self);
 try
  If OpenDialog1.Execute then
  begin
  Screen.Cursor := crHourglass;
  case AlgorithmGroup.ItemIndex of
   0:
   begin
   end;
   1:
    encytObject := Blowfish;
   2:
    encytObject := IDEA;
   3:
    encytObject := RC5;
   4:
    encytObject := RC4;
   5:
    encytObject := DES;
  end;{Case}
  if AlgorithmGroup.ItemIndex > 0 then begin
     encytObject.Key := '1234567890123456';
     encytObject.InputType := SourceFile;
     encytObject.CipherMode := TCipherMode(CipherModeGroup.ItemIndex);
     if encytObject.CipherMode > ECBMode then
        encytObject.IVector := IVectorEdit.Text;
     encytObject.InputFilePath := OpenDialog1.FileName;
     encytObject.OutputFilePath := ChangeFileExt(OpenDialog1.FileName, '.ddd');
     startTime := timeGetTime;
     encytObject.DecipherData(False);
     {gIV:= encytObject.IVector;}
     TimePanel.Caption := IntToStr(timeGetTime - startTime);
  end;{if}
  end;{if}
 finally
   IDEA.free;
   md5hash.free;
   Blowfish.free;
   RC5.free;
   RC4.free;
   DES.free;
   Screen.Cursor := crDefault;
 end;
end;



end.
