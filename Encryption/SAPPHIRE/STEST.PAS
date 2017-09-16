{ stest.pas

  Sapphire II stream cipher test program in Object Oriented Pascal.
  Written by Michael Paul Johnson 20 December 1994 and donated
  to the Public Domain.  This program comes with no warranty of
  any kind.  There is no warranty of any kind on the Sapphire
  Stream Cipher.  Use it at your own risk.

  This program is a reference implementation of the Sapphire II
  Stream Cipher, which is represented in the sapphire object.

  This program will encrypt or decrypt a file based on pass phrase
  key on the command line.  The user interface is a simple
  positional command line interface:

      First parameter:   E to Encrypt, D to Decrypt, or H to Hash
      Second parameter:  Input file name
      Third parameter:   Output file name
      Fourth parameter:  Pass phrase

  There is minimal error checking.  A serious application should
  do more error checking and provide for such things as bad pass
  phrase detection.

  Modified Sapphire variable initialization to make the starting
  point of the variables key dependent, altered the cipher output
  function for better resistance to cryptanalysis, and renamed the
  algorithm to Sapphire II 2 January 1995.
}

program stest;

uses dos, crt;

const BUFFSIZE = 16384;

type
  user_key_type = string[255];      { User's key. }
  hashtype = string[20];            { Cryptographic checksum results. }
  string2 = string[2];              { For hexadecimal bytes. }

  sapphire = object  { This object contains the Sapphire Stream Cipher. }
    procedure initialize(user_key: user_key_type);  { Initialize state. }
    procedure hash_init;              { Initialize state without key. }
    function encrypt(b: byte): byte;  { Encrypt b and return the result. }
    function decrypt(b: byte): byte;  { Decrypt b and return the result. }
    procedure hash_final(var hash: hashtype); { Compute final hash value. }
    procedure burn;                   { Destroy internal key information. }

    private

    rotor,                            { Rotor and ratchet are used to help }
    ratchet,                          { Continually shuffle the "cards."   }
    avalanche,                        { Data dependent index. }
    last_plain,                       { Previous plain text byte. }
    last_cipher: byte;                { Previous cipher text byte. }
    cards: array[0..255] of byte;     { Array to hold a permutation of all }
    end;                              { possible bytes. }

var infile, outfile: file;          { Input and output files. }
  reportfile: text;                 { Output file for text reports. }
  inname, outname: string;          { Input and output file names. }
  user_key: user_key_type;          { Pass phrase. }
  hash: hashtype;                   { Cryptographic check value. }
  stream_cipher: sapphire;          { The stream cipher object. }
  i: integer;                       { Generic index. }
  encryptmode,                      { Command: encrypt, decrypt, hash. }
  u, count: word;                   { Count of bytes in buffer. }
  buffer: array[1..BUFFSIZE] of byte;  { File read/write buffer. }
  b: byte;

procedure sapphire.hash_init;
  var i, j: integer;
  begin
    rotor := 1;           { Make sure we start key in a known place. }
    ratchet := 3;
    avalanche := 5;
    last_plain := 7;
    last_cipher := 11;

    j := 255;
    for i := 0 to 255 do  { Start with cards all in inverse order. }
      begin
        cards[i] := j;
        dec(j);
      end;
  end;

procedure sapphire.initialize(user_key: user_key_type);
  { Sets up key for use by the stream cipher, based on user_key. }
  var keypos: integer;    { Index of current byte of user key. }
    toswap,               { Index for shuffling cards with. }
    swaptemp,             { For holding bytes while swapping. }
    rsum,                 { Function of key bytes processed to now. }
    i, j: byte;           { Indexes into key.cards. }

  function keyrand(limit: integer): byte;
    var u, v, mask: word;
    begin
      if limit > 0 then
        begin
          v := 0;
          mask := 1;
          while mask < limit do
            mask := (mask shl 1) + 1;
          repeat
            rsum := (cards[rsum] + ord(user_key[keypos])) and $FF;
            inc(keypos);
            if keypos > ord(user_key[0]) then
              begin
                keypos := 1;
                rsum := (rsum + ord(user_key[0])) and $FF;
              end;
            u := mask and rsum;
            inc(v);
            if v > 11 then
            u := u mod limit;
          until u <= limit;
          keyrand := u;
        end
      else
        begin
          keyrand := 0
        end
    end;

  begin
    if length(user_key) = 0 then
      hash_init
    else
      begin
        for i := 0 to 255 do  { Start with cards all in order. }
        cards[i] := i;
        keypos := 1;        { Start with first byte of user  }
        toswap := 0;
        rsum := 0;
        for i := 255 downto 0 do  { Swap elements.  Some may get swaped back }
          begin                   { and some may get swapped with self. }
            toswap := keyrand(i);
            swaptemp := cards[i];
            cards[i] := cards[toswap];
            cards[toswap] := swaptemp;
          end;
        rotor := cards[1];           { Make sure we start key in a known place. }
        ratchet := cards[3];
        avalanche := cards[5];
        last_plain := cards[7];
        last_cipher := cards[rsum];
    toswap := 0;
    swaptemp := 0;
    rsum := 0;
    keypos := 0;
      end
  end;

function sapphire.encrypt(b: byte): byte;
  var swaptemp: byte;
  begin
    ratchet := (ratchet + cards[rotor]) and $FF;
    inc(rotor);
    swaptemp := cards[last_cipher];      { Round-robin swap. }
    cards[last_cipher] := cards[ratchet];
    cards[ratchet] := cards[last_plain];
    cards[last_plain] := cards[rotor];
    cards[rotor] := swaptemp;
    avalanche := (avalanche + cards[swaptemp]) and $FF;
    last_cipher := b xor
                 cards[(cards[ratchet] + cards[rotor]) and $FF] xor
                 cards[cards[(cards[last_plain] +
                              cards[last_cipher] +
                              cards[avalanche]) and $FF]];
    last_plain := b;
    encrypt := last_cipher;
  end;

function sapphire.decrypt(b: byte): byte;
  var swaptemp: byte;
  begin
    ratchet := ratchet + cards[rotor];
    inc(rotor);
    swaptemp := cards[last_cipher];
    cards[last_cipher] := cards[ratchet];
    cards[ratchet] := cards[last_plain];
    cards[last_plain] := cards[rotor];
    cards[rotor] := swaptemp;
    avalanche := avalanche + cards[swaptemp];
    last_plain := b xor
                  cards[(cards[ratchet] + cards[rotor]) and $FF] xor
                  cards[cards[(cards[last_plain] +
                               cards[last_cipher] +
                               cards[avalanche]) and $FF]];
    last_cipher := b;
    decrypt := last_plain;
  end;

procedure sapphire.hash_final(var hash: hashtype);
  var i: integer;
  begin
    for i := 255 downto 0 do
      encrypt(i);
    hash[0] := chr(20);
    for i := 1 to 20 do
      hash[i] := chr(encrypt(0));
  end;

procedure sapphire.burn;
  begin
    fillchar(cards, sizeof(cards), 0);
    rotor := 0;
    ratchet := 0;
    avalanche := 0;
    last_plain := 0;
    last_cipher := 0;
  end;

function tohex(inbyte: byte): string2;
{ For use in debugging printouts, etc. }
  var
    nibble: byte;
    temp: string2;
  begin
    nibble := inbyte shr 4;
    if nibble < 10 then
      temp := chr(nibble + 48)
    else
      temp := chr(nibble + 55);
    nibble := inbyte and $0F;
    if nibble < 10 then
      temp := temp + chr(nibble + 48)
    else
      temp := temp + chr(nibble + 55);
    tohex := temp;
  end;

procedure help;
  begin
    writeln(
    'Sapphire test program written by Michael Paul Johnson 2 January 1995');
    writeln(
    'and donated to the Public Domain.  No warranty, expressed or implied.');
    writeln('Use this program at your own risk.');
    writeln('Don''t forget your passphrase.  No passphrase, no data.');
    writeln;
    writeln('Syntax:');
    writeln(paramstr(0),' E|D|H inname outname passphrase');
    writeln('  E = Encrypt');
    writeln('  D = Decrypt');
    writeln('  H = Generate keyed cryptographic Hash');
    halt(1)
  end;

begin { main program }
  if paramcount < 3 then
    help;
  if (paramstr(1) = 'E') or (paramstr(1) = 'e') then
    encryptmode := 0
  else if (paramstr(1) = 'D') or (paramstr(1) = 'd') then
    encryptmode := 1
  else if (paramstr(1) = 'H') or (paramstr(1) = 'h') then
    encryptmode := 2
  else
    help;
  inname := paramstr(2);
  outname := paramstr(3);
  if paramcount >= 4 then
    user_key := paramstr(4)
  else
    user_key := '';
  for i := 5 to paramcount do
    user_key := user_key + ' ' + paramstr(i);
  stream_cipher.initialize(user_key);
  assign(infile, inname);
  reset(infile, 1);
  if encryptmode = 2 then
    begin
      assign(reportfile, outname);
      rewrite(reportfile);
    end
  else
    begin
      assign(outfile, outname);
      rewrite(outfile, 1);
    end;
  if encryptmode = 0 then
    begin
      repeat
        blockread(infile, buffer, BUFFSIZE, count);
        for u := 1 to count do
          buffer[u] := stream_cipher.encrypt(buffer[u]);
        blockwrite(outfile, buffer, count);
      until (count = 0);
      close(outfile);
    end
  else if encryptmode = 1 then
    begin
      repeat
        blockread(infile, buffer, BUFFSIZE, count);
        for u := 1 to count do
          buffer[u] := stream_cipher.decrypt(buffer[u]);
        blockwrite(outfile, buffer, count);
      until (count = 0);
      close(outfile);
    end
  else
    begin
      repeat
        blockread(infile, buffer, BUFFSIZE, count);
        for u := 1 to count do
          buffer[u] := stream_cipher.encrypt(buffer[u]);
      until (count = 0);
      { Output text report of hash. }
      stream_cipher.hash_final(hash);
      writeln(reportfile, 'Check value for ',inname,' is:');
      for i := 1 to 20 do
        write(reportfile, tohex(ord(hash[i])));
      writeln(reportfile);
      close(reportfile);
    end;
  close(infile);
  stream_cipher.burn;
end.

