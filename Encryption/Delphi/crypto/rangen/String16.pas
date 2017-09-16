unit String16;
{$DEFINE DELPHI16}
interface
{$IFDEF DELPHI16}
  procedure SetLength(var S: string; Len: Integer);
  procedure SetString(var Dst: string; Src: PChar; Len: Integer);
{$ENDIF}
implementation
{$IFDEF DELPHI16}
  procedure SetLength(var S: string; Len: Integer);
  begin
    if Len > 255 then
      S[0] := Chr(255)
    else
      S[0] := Chr(Len)
  end;

  procedure SetString(var Dst: string; Src: PChar; Len: Integer);
  begin
    if Len > 255 then
      Move(Src^, Dst[1], 255)
    else
      Move(Src^, Dst[1], Len);
    SetLength(Dst, Len);
  end;
{$ENDIF}
end.
