program BlowFish_CBC_Example;

  {*****************************************************************}
  {*******      BLW-CBC.pas (c) 1997 by Dutra de Lacerda     *******}
  {*******   E-Mail address:  dulac@ip.pt   FIDO: 2:362/20   *******}
  {*******  Example program of the usage of the BLW_CBC Unit *******}
  {*******        Hereby donated to the public domain        *******}
  {*****************************************************************}

uses BfishCBC, Dos;

{$M $A000,0,$28000}

var
  Key : String;
  InputFile,
  OutputFile : String;
  Choice : String[3];
  Input,
  Output : file;
  Hour,
  Minute,
  Second,
  Second100 : Word;


  function File_Exists(const FileName : String) : Boolean;
  var
    F : file;

  begin
    Assign(F, FileName);
        {$i-} Reset(F, 1); {$i+}
    File_Exists := IoResult = 0;
  end;


begin
  WriteLn;
  WriteLn(#9, ':::::::::::::: Blowfish-CBC CRYPT-Utility v1.5.B ::::::::::::::');
  WriteLn(#9, '::  Public Domain by: Dutra de Lacerda,  Email: dulac@ip.pt  ::');
  WriteLn(#9, ':::::::::::: PROTECTS your FILES, and your PRIVACY ::::::::::::');
  Choice := Copy(ParamStr(1), 1, 3);
  Choice[1] := Upcase(Choice[1]);
  InputFile := ParamStr(3);
  OutputFile := ParamStr(4);
  if ((Choice = 'E') or (Choice = 'D')) and
  (ParamStr(2) <> '') and
  (ParamStr(3) <> '') then
    begin
      if File_Exists(ParamStr(3)) then
        begin
          Key := Copy(ParamStr(2), 1, 56);
          WriteLn(#13, #10, 'Initializing key');
          BLW_CBC_INIT(Key, 8);
          GetTime(Hour, Minute, Second, Second100);
          WriteLn(Hour, ':', Minute, ':', Second, ':', Second100);

          if Choice = 'E' then
            BLW_CBC_CRYPT(InputFile, OutputFile)
          else
            BLW_CBC_DECRYPT(InputFile, OutputFile);

          GetTime(Hour, Minute, Second, Second100);
          WriteLn(Hour, ':', Minute, ':', Second, ':', Second100);
          WriteLn(OutputFile, ' written!');

        end {If 3th Argument (a File) exists}
      else {If 3th Argument (a File) does not exists}
        Writeln(#13, #10, 'File ',ParamStr(3),' does not exist! Aborting...');
    end {IF-else there Are 3 Arguments}
  else
    begin
      WriteLn;
      WriteLn(#9, 'ีอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออธ');
      WriteLn(#9, 'ณ ฑฑฑฑฑฑฑฑฑฑฑฑฑฑฑฑฑ  BlowFish-CBC 1.5 Help  ฑฑฑฑฑฑฑฑฑฑฑฑฑฑฑฑฑ ณ');
      WriteLn(#9, 'รฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤด');
      WriteLn(#9, 'ณ     BLW-CBC (E|D) <PassFrase> <InputFile> [<OutputFile>]    ณ');
      WriteLn(#9, 'ณ              ณ ณ                   |             |          ณ');
      WriteLn(#9, 'ณ   Encrypt ฤฤฤู ภฤฤฤ Decrypt     Origin!   Optional Argument ณ');
      WriteLn(#9, 'รฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤฤด');
      WriteLn(#9, 'ณ For Best Protection Use LONG PassFrases, with ''_'' as spaces ณ');
      WriteLn(#9, 'ิอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออพ');
      WriteLn(#9, '                                                               ');
      WriteLn(#9, '    Example          Mode       Frase        File              ');
      WriteLn(#9, '    ~~~~~~~           |           |            |               ');
      WriteLn(#9, ' C:\SECRET>  BLW-CBC  E  MyOwn_Secret_Key  myfile.txt  <Enter> ');
    end;
end.
