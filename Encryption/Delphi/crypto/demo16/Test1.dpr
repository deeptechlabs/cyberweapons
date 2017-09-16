program Test1;

uses
  Forms,
  Frm1 in 'FRM1.PAS' {cryptfrm},
  Md5unit in '\DELPHI\CRYPTO\MD5\MD5UNIT.PAS',
  Blowunit in '\DELPHI\CRYPTO\BLOWFISH\BLOWUNIT.PAS',
  Ideaunit in '\DELPHI\CRYPTO\IDEA\IDEAUNIT.PAS',
  Rc5unit in '\DELPHI\CRYPTO\RC5\RC5UNIT.PAS',
  Cryptcon in '\DELPHI\CRYPTO\CRYPTO~1\CRYPTCON.PAS',
  Rc4unit in '\DELPHI\CRYPTO\RC4\RC4UNIT.PAS',
  Desunit2 in '\DELPHI\CRYPTO\DES\DESUNIT2.PAS';

{$R *.RES}

begin
  Application.CreateForm(Tcryptfrm, cryptfrm);
  Application.Run;
end.
