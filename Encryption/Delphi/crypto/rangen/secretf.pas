unit Secretf;
{******************************************************************************}
{Displays the form to get user input to seed the random number generator.
 The time between key presses is used to feed the MD5 algorithm to produce
 Random Numbers.

 The Random Number Generator is based loosely on the one mentioned in the
 PGP Mail and in a document by Brain J. Harvey <bjh@northshore.ecosoft.com>

 ******************************************************************************}

{This code is copyright by CRYPTOCard Corporation 1996.  You may use it as is,
 or preferably MODIFY it(the interface). It is placed into the public domain.
 Spinning Cube Component by Unknown Author(Thanks).

 It has been setup to be used as a DLL

 Author: Greg Carter, CRPYTOCard Corporation, gregc@cryptocard.com
 ******************************************************************************}

interface

uses WinTypes, WinProcs, Classes, Graphics, Forms, Controls, Buttons,
  StdCtrls, ExtCtrls, Ccube, MD5unit, mmsystem, SysUtils, String16;

type
  TSecretFrm = class(TForm)
    OKBtn: TBitBtn;
    CancelBtn: TBitBtn;
    HelpBtn: TBitBtn;
    Bevel1: TBevel;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    KeyEdit: TEdit;
    PressLabel: TLabel;
    CountLable: TLabel;
    Label4: TLabel;
    CubeSpin1: TCubeSpin;
    procedure FormKeyUp(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure FormKeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure FormDestroy(Sender: TObject);
  private
    { Private declarations }
   FgKeyPresses: BYTE;
   FRanMD5: TMD5;
   FOutputArray: Array[0..15] of char;
   FLastTime: LongInt;
   FNewSecret: String[32];

  public
    { Public declarations }
  function Byte2Hex(numb : PByte; Len: WORD): String;

  end;

var
  SecretFrm: TSecretFrm;

Const
MAXKEYPRESS = 8;

procedure GetSecret(Handle: THandle; var Secret: String); export;

implementation

{$R *.DFM}
procedure GetSecret(Handle: THandle; var Secret: String);
begin
 Application.Handle := Handle;
 SecretFrm := TSecretFrm.Create(Application);
 try
  SecretFrm.FgKeyPresses := 0;
  SecretFrm.ShowModal;
  if SecretFrm.ModalResult = mrOk then
    Secret := SecretFrm.FNewSecret
  else
    Secret := '';
 finally
  SecretFrm.Free;
  SecretFrm.FNewSecret := '00000000000000000000000000000000000000000000000';
 end;
end;


procedure TSecretFrm.FormKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
var
 interval, cTime: LongInt;

begin
  if Key <> VK_SPACE then
   exit;
  CubeSpin1.ZSpinOn := Not CubeSpin1.ZSpinOn;
  CubeSpin1.XSpinOn := Not CubeSpin1.XSpinOn;
  inc(SecretFrm.FgKeyPresses);
  if SecretFrm.FgKeyPresses <= MAXKEYPRESS then begin
   cTime := timeGetTime;
   interval := cTime - SecretFrm.FLastTime;
   SecretFrm.FLastTime := cTime;
   SecretFrm.FRanMD5.pInputArray := @interval;
   SecretFrm.FRanMD5.InputLength := SizeOf(interval);
   SecretFrm.FRanMD5.MD5_Hash_Bytes;
   PressLabel.Caption := IntToStr(SecretFrm.FgKeyPresses);
  end;
  if SecretFrm.FgKeyPresses = MAXKEYPRESS then begin
    SecretFrm.FRanMD5.pOutputArray := @SecretFrm.FOutputArray;
    SecretFrm.FRanMD5.MD5_Finish;
    SecretFrm.FNewSecret := Byte2Hex(@SecretFrm.FOutputArray, SizeOf(SecretFrm.FOutputArray));
    KeyEdit.Text := SecretFrm.FNewSecret;
    OKBtn.Visible := True;
    Label4.Visible := True;
  end;
  Key := 0;
end;

procedure TSecretFrm.FormCreate(Sender: TObject);
begin
 FgKeyPresses := 0;
 FRanMD5 := TMD5.Create(Self);
 FRanMD5.MD5_Initialize;
 FLastTime := timeGetTime;
 FRanMD5.pInputArray := @FLastTime;
 FRanMD5.InputLength := SizeOf(FLastTime);
 FRanMD5.MD5_Hash_Bytes;
end;
function TSecretFrm.Byte2Hex(numb : PByte; Len: WORD): String;
{------------------------------------------------------------------------------
Purpose:   Convert byte array into a string representing the array in Hex
            notation.  Puts its results in FPacketStr.
 ------------------------------------------------------------------------------}
Const
    HexChars : Array[0..15] of Char = '0123456789ABCDEF';
var
    Str1: String;
    i, j: WORD;
begin
 j := 1; Str1:= '';
 for i := 1 to Len  do begin
  Str1[j] := HexChars[numb^ shr  4];
  Str1[j + 1] := HexChars[numb^ and 15];
  Inc(numb);
  SetLength(Str1, j + 1);
  Inc(j, 2);
 end;{for}
 Result := Str1;
end; { Byte2Hex }

procedure TSecretFrm.FormShow(Sender: TObject);
begin
  KeyEdit.SetFocus;
  CubeSpin1.Continuous := True;
end;

procedure TSecretFrm.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
   Key := 0;
end;

procedure TSecretFrm.FormDestroy(Sender: TObject);
begin
 FRanMD5.Free;
end;

end.
