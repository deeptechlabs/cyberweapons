program Test1;

uses
  Forms,
  Frm1 in 'Frm1.pas' {cryptfrm},
  Blowunit in '\Program Files\Borland\Delphi 2.0\crypto routines\BLOWFISH\Blowunit.pas',
  Ideaunit in '\Program Files\Borland\Delphi 2.0\crypto routines\IDEA\Ideaunit.pas',
  Md5unit in '\Program Files\Borland\Delphi 2.0\crypto routines\MD5\Md5unit.pas',
  Rc4unit in '\Program Files\Borland\Delphi 2.0\crypto routines\RC4\rc4unit.pas',
  Rc5unit in '\Program Files\Borland\Delphi 2.0\crypto routines\RC5\Rc5unit.pas',
  Desunit2 in '\Program Files\Borland\Delphi 2.0\crypto routines\DES\desunit2.pas';

{$R *.RES}

begin
  Application.CreateForm(Tcryptfrm, cryptfrm);
  Application.Run;
end.
