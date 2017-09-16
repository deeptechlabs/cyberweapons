void __declspec(naked) __cdecl RIPEMD160Transform(unsigned long* H, unsigned long* x)
{
  __asm{
	push ebp
	push esi
	push edi
	push ebx
	mov eax, [esp+20]
	mov edx, [esp+24]
	sub esp, 64
	mov edi, [edx]
	mov ebp, [edx+4]
	mov [esp], edi
	mov [esp+4], ebp
	mov edi, [edx+8]
	mov ebp, [edx+12]
	mov [esp+8], edi
	mov [esp+12], ebp
	mov edi, [edx+16]
	mov ebp, [edx+20]
	mov [esp+16], edi
	mov [esp+20], ebp
	mov edi, [edx+24]
	mov ebp, [edx+28]
	mov [esp+24], edi
	mov [esp+28], ebp
	mov edi, [edx+32]
	mov ebp, [edx+36]
	mov [esp+32], edi
	mov [esp+36], ebp
	mov edi, [edx+40]
	mov ebp, [edx+44]
	mov [esp+40], edi
	mov [esp+44], ebp
	mov edi, [edx+48]
	mov ebp, [edx+52]
	mov [esp+48], edi
	mov [esp+52], ebp
	mov edi, [edx+56]
	mov ebp, [edx+60]
	mov [esp+56], edi
	mov [esp+60], ebp
	mov edi, [eax+16]
	mov edx, [eax+12]
	mov ecx, [eax+8]
	mov ebx, [eax+4]
	mov eax, [eax]
	push edi
	push edx
	push ecx
	push ebx
	push eax
/* left half */
	mov ebp, ecx
/* Subround 0 */
	xor ebp, edx
	add eax, [esp+20]
	xor ebp, ebx
	rol ecx, 10
	add eax, ebp
	mov ebp, ebx
	rol eax, 11
	add eax, edi

/* Subround 1 */
	xor ebp, ecx
	add edi, [esp+24]
	xor ebp, eax
	rol ebx, 10
	add edi, ebp
	mov ebp, eax
	rol edi, 14
	add edi, edx

/* Subround 2 */
	xor ebp, ebx
	add edx, [esp+28]
	xor ebp, edi
	rol eax, 10
	add edx, ebp
	mov ebp, edi
	rol edx, 15
	add edx, ecx

/* Subround 3 */
	xor ebp, eax
	add ecx, [esp+32]
	xor ebp, edx
	rol edi, 10
	add ecx, ebp
	mov ebp, edx
	rol ecx, 12
	add ecx, ebx

/* Subround 4 */
	xor ebp, edi
	add ebx, [esp+36]
	xor ebp, ecx
	rol edx, 10
	add ebx, ebp
	mov ebp, ecx
	rol ebx, 5
	add ebx, eax

/* Subround 5 */
	xor ebp, edx
	add eax, [esp+40]
	xor ebp, ebx
	rol ecx, 10
	add eax, ebp
	mov ebp, ebx
	rol eax, 8
	add eax, edi

/* Subround 6 */
	xor ebp, ecx
	add edi, [esp+44]
	xor ebp, eax
	rol ebx, 10
	add edi, ebp
	mov ebp, eax
	rol edi, 7
	add edi, edx

/* Subround 7 */
	xor ebp, ebx
	add edx, [esp+48]
	xor ebp, edi
	rol eax, 10
	add edx, ebp
	mov ebp, edi
	rol edx, 9
	add edx, ecx

/* Subround 8 */
	xor ebp, eax
	add ecx, [esp+52]
	xor ebp, edx
	rol edi, 10
	add ecx, ebp
	mov ebp, edx
	rol ecx, 11
	add ecx, ebx

/* Subround 9 */
	xor ebp, edi
	add ebx, [esp+56]
	xor ebp, ecx
	rol edx, 10
	add ebx, ebp
	mov ebp, ecx
	rol ebx, 13
	add ebx, eax

/* Subround 10 */
	xor ebp, edx
	add eax, [esp+60]
	xor ebp, ebx
	rol ecx, 10
	add eax, ebp
	mov ebp, ebx
	rol eax, 14
	add eax, edi

/* Subround 11 */
	xor ebp, ecx
	add edi, [esp+64]
	xor ebp, eax
	rol ebx, 10
	add edi, ebp
	mov ebp, eax
	rol edi, 15
	add edi, edx

/* Subround 12 */
	xor ebp, ebx
	add edx, [esp+68]
	xor ebp, edi
	rol eax, 10
	add edx, ebp
	mov ebp, edi
	rol edx, 6
	add edx, ecx

/* Subround 13 */
	xor ebp, eax
	add ecx, [esp+72]
	xor ebp, edx
	rol edi, 10
	add ecx, ebp
	mov ebp, edx
	rol ecx, 7
	add ecx, ebx

/* Subround 14 */
	xor ebp, edi
	add ebx, [esp+76]
	xor ebp, ecx
	rol edx, 10
	add ebx, ebp
	mov ebp, ecx
	rol ebx, 9
	add ebx, eax

/* Subround 15 */
	xor ebp, edx
	add eax, [esp+80]
	xor ebp, ebx
	rol ecx, 10
	add eax, ebp
	mov ebp, ebx
	rol eax, 8
	add eax, edi

/* Subround 16 */
	xor ebp, ecx
	and ebp, eax
	mov esi, [esp+48]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1518500249]
	mov ebp, eax
	rol edi, 7
	add edi, edx

/* Subround 17 */
	xor ebp, ebx
	and ebp, edi
	mov esi, [esp+36]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1518500249]
	mov ebp, edi
	rol edx, 6
	add edx, ecx

/* Subround 18 */
	xor ebp, eax
	and ebp, edx
	mov esi, [esp+72]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1518500249]
	mov ebp, edx
	rol ecx, 8
	add ecx, ebx

/* Subround 19 */
	xor ebp, edi
	and ebp, ecx
	mov esi, [esp+24]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1518500249]
	mov ebp, ecx
	rol ebx, 13
	add ebx, eax

/* Subround 20 */
	xor ebp, edx
	and ebp, ebx
	mov esi, [esp+60]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1518500249]
	mov ebp, ebx
	rol eax, 11
	add eax, edi

/* Subround 21 */
	xor ebp, ecx
	and ebp, eax
	mov esi, [esp+44]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1518500249]
	mov ebp, eax
	rol edi, 9
	add edi, edx

/* Subround 22 */
	xor ebp, ebx
	and ebp, edi
	mov esi, [esp+80]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1518500249]
	mov ebp, edi
	rol edx, 7
	add edx, ecx

/* Subround 23 */
	xor ebp, eax
	and ebp, edx
	mov esi, [esp+32]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1518500249]
	mov ebp, edx
	rol ecx, 15
	add ecx, ebx

/* Subround 24 */
	xor ebp, edi
	and ebp, ecx
	mov esi, [esp+68]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1518500249]
	mov ebp, ecx
	rol ebx, 7
	add ebx, eax

/* Subround 25 */
	xor ebp, edx
	and ebp, ebx
	mov esi, [esp+20]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1518500249]
	mov ebp, ebx
	rol eax, 12
	add eax, edi

/* Subround 26 */
	xor ebp, ecx
	and ebp, eax
	mov esi, [esp+56]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1518500249]
	mov ebp, eax
	rol edi, 15
	add edi, edx

/* Subround 27 */
	xor ebp, ebx
	and ebp, edi
	mov esi, [esp+40]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1518500249]
	mov ebp, edi
	rol edx, 9
	add edx, ecx

/* Subround 28 */
	xor ebp, eax
	and ebp, edx
	mov esi, [esp+28]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1518500249]
	mov ebp, edx
	rol ecx, 11
	add ecx, ebx

/* Subround 29 */
	xor ebp, edi
	and ebp, ecx
	mov esi, [esp+76]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1518500249]
	mov ebp, ecx
	rol ebx, 7
	add ebx, eax

/* Subround 30 */
	xor ebp, edx
	and ebp, ebx
	mov esi, [esp+64]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1518500249]
	mov ebp, ebx
	rol eax, 13
	add eax, edi

/* Subround 31 */
	xor ebp, ecx
	and ebp, eax
	mov esi, [esp+52]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1518500249]
	mov ebp, eax
	rol edi, 12
	add edi, edx

/* Subround 32 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+32]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1859775393]
	mov ebp, edi
	rol edx, 11
	add edx, ecx

/* Subround 33 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+60]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1859775393]
	mov ebp, edx
	rol ecx, 13
	add ecx, ebx

/* Subround 34 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+76]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1859775393]
	mov ebp, ecx
	rol ebx, 6
	add ebx, eax

/* Subround 35 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+36]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1859775393]
	mov ebp, ebx
	rol eax, 7
	add eax, edi

/* Subround 36 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+56]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1859775393]
	mov ebp, eax
	rol edi, 14
	add edi, edx

/* Subround 37 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+80]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1859775393]
	mov ebp, edi
	rol edx, 9
	add edx, ecx

/* Subround 38 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+52]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1859775393]
	mov ebp, edx
	rol ecx, 13
	add ecx, ebx

/* Subround 39 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+24]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1859775393]
	mov ebp, ecx
	rol ebx, 15
	add ebx, eax

/* Subround 40 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+28]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1859775393]
	mov ebp, ebx
	rol eax, 14
	add eax, edi

/* Subround 41 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+48]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1859775393]
	mov ebp, eax
	rol edi, 8
	add edi, edx

/* Subround 42 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+20]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1859775393]
	mov ebp, edi
	rol edx, 13
	add edx, ecx

/* Subround 43 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+44]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1859775393]
	mov ebp, edx
	rol ecx, 6
	add ecx, ebx

/* Subround 44 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+72]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1859775393]
	mov ebp, ecx
	rol ebx, 5
	add ebx, eax

/* Subround 45 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+64]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1859775393]
	mov ebp, ebx
	rol eax, 12
	add eax, edi

/* Subround 46 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+40]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1859775393]
	mov ebp, eax
	rol edi, 7
	add edi, edx

/* Subround 47 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+68]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1859775393]
	mov ebp, edi
	rol edx, 5
	add edx, ecx

/* Subround 48 */
	xor ebp, edx
	and ebp, eax
	mov esi, [esp+24]
	xor ebp, edi
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+-1894007588]
	mov ebp, edx
	rol ecx, 11
	add ecx, ebx

/* Subround 49 */
	xor ebp, ecx
	and ebp, edi
	mov esi, [esp+56]
	xor ebp, edx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+-1894007588]
	mov ebp, ecx
	rol ebx, 12
	add ebx, eax

/* Subround 50 */
	xor ebp, ebx
	and ebp, edx
	mov esi, [esp+64]
	xor ebp, ecx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+-1894007588]
	mov ebp, ebx
	rol eax, 14
	add eax, edi

/* Subround 51 */
	xor ebp, eax
	and ebp, ecx
	mov esi, [esp+60]
	xor ebp, ebx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+-1894007588]
	mov ebp, eax
	rol edi, 15
	add edi, edx

/* Subround 52 */
	xor ebp, edi
	and ebp, ebx
	mov esi, [esp+20]
	xor ebp, eax
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+-1894007588]
	mov ebp, edi
	rol edx, 14
	add edx, ecx

/* Subround 53 */
	xor ebp, edx
	and ebp, eax
	mov esi, [esp+52]
	xor ebp, edi
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+-1894007588]
	mov ebp, edx
	rol ecx, 15
	add ecx, ebx

/* Subround 54 */
	xor ebp, ecx
	and ebp, edi
	mov esi, [esp+68]
	xor ebp, edx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+-1894007588]
	mov ebp, ecx
	rol ebx, 9
	add ebx, eax

/* Subround 55 */
	xor ebp, ebx
	and ebp, edx
	mov esi, [esp+36]
	xor ebp, ecx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+-1894007588]
	mov ebp, ebx
	rol eax, 8
	add eax, edi

/* Subround 56 */
	xor ebp, eax
	and ebp, ecx
	mov esi, [esp+72]
	xor ebp, ebx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+-1894007588]
	mov ebp, eax
	rol edi, 9
	add edi, edx

/* Subround 57 */
	xor ebp, edi
	and ebp, ebx
	mov esi, [esp+32]
	xor ebp, eax
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+-1894007588]
	mov ebp, edi
	rol edx, 14
	add edx, ecx

/* Subround 58 */
	xor ebp, edx
	and ebp, eax
	mov esi, [esp+48]
	xor ebp, edi
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+-1894007588]
	mov ebp, edx
	rol ecx, 5
	add ecx, ebx

/* Subround 59 */
	xor ebp, ecx
	and ebp, edi
	mov esi, [esp+80]
	xor ebp, edx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+-1894007588]
	mov ebp, ecx
	rol ebx, 6
	add ebx, eax

/* Subround 60 */
	xor ebp, ebx
	and ebp, edx
	mov esi, [esp+76]
	xor ebp, ecx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+-1894007588]
	mov ebp, ebx
	rol eax, 8
	add eax, edi

/* Subround 61 */
	xor ebp, eax
	and ebp, ecx
	mov esi, [esp+40]
	xor ebp, ebx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+-1894007588]
	mov ebp, eax
	rol edi, 6
	add edi, edx

/* Subround 62 */
	xor ebp, edi
	and ebp, ebx
	mov esi, [esp+44]
	xor ebp, eax
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+-1894007588]
	mov ebp, edi
	rol edx, 5
	add edx, ecx

/* Subround 63 */
	xor ebp, edx
	and ebp, eax
	mov esi, [esp+28]
	xor ebp, edi
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+-1894007588]
	mov ebp, edx
	rol ecx, 12
	add ecx, ebx

	mov ebp, edi
	nop
/* Subround 64 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+36]
	xor ebp, ecx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+-1454113458]
	mov ebp, edx
	rol ebx, 9
	add ebx, eax

/* Subround 65 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+20]
	xor ebp, ebx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+-1454113458]
	mov ebp, ecx
	rol eax, 15
	add eax, edi

/* Subround 66 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+40]
	xor ebp, eax
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+-1454113458]
	mov ebp, ebx
	rol edi, 5
	add edi, edx

/* Subround 67 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+56]
	xor ebp, edi
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+-1454113458]
	mov ebp, eax
	rol edx, 11
	add edx, ecx

/* Subround 68 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+48]
	xor ebp, edx
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+-1454113458]
	mov ebp, edi
	rol ecx, 6
	add ecx, ebx

/* Subround 69 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+68]
	xor ebp, ecx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+-1454113458]
	mov ebp, edx
	rol ebx, 8
	add ebx, eax

/* Subround 70 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+28]
	xor ebp, ebx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+-1454113458]
	mov ebp, ecx
	rol eax, 13
	add eax, edi

/* Subround 71 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+60]
	xor ebp, eax
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+-1454113458]
	mov ebp, ebx
	rol edi, 12
	add edi, edx

/* Subround 72 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+76]
	xor ebp, edi
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+-1454113458]
	mov ebp, eax
	rol edx, 5
	add edx, ecx

/* Subround 73 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+24]
	xor ebp, edx
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+-1454113458]
	mov ebp, edi
	rol ecx, 12
	add ecx, ebx

/* Subround 74 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+32]
	xor ebp, ecx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+-1454113458]
	mov ebp, edx
	rol ebx, 13
	add ebx, eax

/* Subround 75 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+52]
	xor ebp, ebx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+-1454113458]
	mov ebp, ecx
	rol eax, 14
	add eax, edi

/* Subround 76 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+64]
	xor ebp, eax
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+-1454113458]
	mov ebp, ebx
	rol edi, 11
	add edi, edx

/* Subround 77 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+44]
	xor ebp, edi
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+-1454113458]
	mov ebp, eax
	rol edx, 8
	add edx, ecx

/* Subround 78 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+80]
	xor ebp, edx
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+-1454113458]
	mov ebp, edi
	rol ecx, 5
	add ecx, ebx

/* Subround 79 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+72]
	xor ebp, ecx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+-1454113458]
	mov ebp, edx
	rol ebx, 6
	add ebx, eax

/* save left result */
	push edi
	push edx
	push ecx
	push ebx
	push eax
/* reloading chain variables */
	mov edi, [esp+36]
	mov edx, [esp+32]
	mov ecx, [esp+28]
	mov ebx, [esp+24]
	mov eax, [esp+20]
/* right half */
	mov ebp, edx
/* Subround 0 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+60]
	xor ebp, ebx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1352829926]
	mov ebp, ecx
	rol eax, 8
	add eax, edi

/* Subround 1 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+96]
	xor ebp, eax
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1352829926]
	mov ebp, ebx
	rol edi, 9
	add edi, edx

/* Subround 2 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+68]
	xor ebp, edi
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1352829926]
	mov ebp, eax
	rol edx, 9
	add edx, ecx

/* Subround 3 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+40]
	xor ebp, edx
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1352829926]
	mov ebp, edi
	rol ecx, 11
	add ecx, ebx

/* Subround 4 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+76]
	xor ebp, ecx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1352829926]
	mov ebp, edx
	rol ebx, 13
	add ebx, eax

/* Subround 5 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+48]
	xor ebp, ebx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1352829926]
	mov ebp, ecx
	rol eax, 15
	add eax, edi

/* Subround 6 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+84]
	xor ebp, eax
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1352829926]
	mov ebp, ebx
	rol edi, 15
	add edi, edx

/* Subround 7 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+56]
	xor ebp, edi
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1352829926]
	mov ebp, eax
	rol edx, 5
	add edx, ecx

/* Subround 8 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+92]
	xor ebp, edx
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1352829926]
	mov ebp, edi
	rol ecx, 7
	add ecx, ebx

/* Subround 9 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+64]
	xor ebp, ecx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1352829926]
	mov ebp, edx
	rol ebx, 7
	add ebx, eax

/* Subround 10 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+100]
	xor ebp, ebx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1352829926]
	mov ebp, ecx
	rol eax, 8
	add eax, edi

/* Subround 11 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+72]
	xor ebp, eax
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1352829926]
	mov ebp, ebx
	rol edi, 11
	add edi, edx

/* Subround 12 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+44]
	xor ebp, edi
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1352829926]
	mov ebp, eax
	rol edx, 14
	add edx, ecx

/* Subround 13 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+80]
	xor ebp, edx
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1352829926]
	mov ebp, edi
	rol ecx, 14
	add ecx, ebx

/* Subround 14 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+52]
	xor ebp, ecx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1352829926]
	mov ebp, edx
	rol ebx, 12
	add ebx, eax

/* Subround 15 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+88]
	xor ebp, ebx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1352829926]
	mov ebp, ecx
	rol eax, 6
	add eax, edi

	mov ebp, ebx
	nop
/* Subround 16 */
	xor ebp, eax
	and ebp, ecx
	mov esi, [esp+64]
	xor ebp, ebx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1548603684]
	mov ebp, eax
	rol edi, 9
	add edi, edx

/* Subround 17 */
	xor ebp, edi
	and ebp, ebx
	mov esi, [esp+84]
	xor ebp, eax
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1548603684]
	mov ebp, edi
	rol edx, 13
	add edx, ecx

/* Subround 18 */
	xor ebp, edx
	and ebp, eax
	mov esi, [esp+52]
	xor ebp, edi
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1548603684]
	mov ebp, edx
	rol ecx, 15
	add ecx, ebx

/* Subround 19 */
	xor ebp, ecx
	and ebp, edi
	mov esi, [esp+68]
	xor ebp, edx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1548603684]
	mov ebp, ecx
	rol ebx, 7
	add ebx, eax

/* Subround 20 */
	xor ebp, ebx
	and ebp, edx
	mov esi, [esp+40]
	xor ebp, ecx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1548603684]
	mov ebp, ebx
	rol eax, 12
	add eax, edi

/* Subround 21 */
	xor ebp, eax
	and ebp, ecx
	mov esi, [esp+92]
	xor ebp, ebx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1548603684]
	mov ebp, eax
	rol edi, 8
	add edi, edx

/* Subround 22 */
	xor ebp, edi
	and ebp, ebx
	mov esi, [esp+60]
	xor ebp, eax
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1548603684]
	mov ebp, edi
	rol edx, 9
	add edx, ecx

/* Subround 23 */
	xor ebp, edx
	and ebp, eax
	mov esi, [esp+80]
	xor ebp, edi
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1548603684]
	mov ebp, edx
	rol ecx, 11
	add ecx, ebx

/* Subround 24 */
	xor ebp, ecx
	and ebp, edi
	mov esi, [esp+96]
	xor ebp, edx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1548603684]
	mov ebp, ecx
	rol ebx, 7
	add ebx, eax

/* Subround 25 */
	xor ebp, ebx
	and ebp, edx
	mov esi, [esp+100]
	xor ebp, ecx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1548603684]
	mov ebp, ebx
	rol eax, 7
	add eax, edi

/* Subround 26 */
	xor ebp, eax
	and ebp, ecx
	mov esi, [esp+72]
	xor ebp, ebx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1548603684]
	mov ebp, eax
	rol edi, 12
	add edi, edx

/* Subround 27 */
	xor ebp, edi
	and ebp, ebx
	mov esi, [esp+88]
	xor ebp, eax
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1548603684]
	mov ebp, edi
	rol edx, 7
	add edx, ecx

/* Subround 28 */
	xor ebp, edx
	and ebp, eax
	mov esi, [esp+56]
	xor ebp, edi
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1548603684]
	mov ebp, edx
	rol ecx, 6
	add ecx, ebx

/* Subround 29 */
	xor ebp, ecx
	and ebp, edi
	mov esi, [esp+76]
	xor ebp, edx
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1548603684]
	mov ebp, ecx
	rol ebx, 15
	add ebx, eax

/* Subround 30 */
	xor ebp, ebx
	and ebp, edx
	mov esi, [esp+44]
	xor ebp, ecx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1548603684]
	mov ebp, ebx
	rol eax, 13
	add eax, edi

/* Subround 31 */
	xor ebp, eax
	and ebp, ecx
	mov esi, [esp+48]
	xor ebp, ebx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1548603684]
	mov ebp, eax
	rol edi, 11
	add edi, edx

/* Subround 32 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+100]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1836072691]
	mov ebp, edi
	rol edx, 9
	add edx, ecx

/* Subround 33 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+60]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1836072691]
	mov ebp, edx
	rol ecx, 7
	add ecx, ebx

/* Subround 34 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+44]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1836072691]
	mov ebp, ecx
	rol ebx, 15
	add ebx, eax

/* Subround 35 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+52]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1836072691]
	mov ebp, ebx
	rol eax, 11
	add eax, edi

/* Subround 36 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+68]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1836072691]
	mov ebp, eax
	rol edi, 8
	add edi, edx

/* Subround 37 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+96]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1836072691]
	mov ebp, edi
	rol edx, 6
	add edx, ecx

/* Subround 38 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+64]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1836072691]
	mov ebp, edx
	rol ecx, 6
	add ecx, ebx

/* Subround 39 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+76]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1836072691]
	mov ebp, ecx
	rol ebx, 14
	add ebx, eax

/* Subround 40 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+84]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1836072691]
	mov ebp, ebx
	rol eax, 12
	add eax, edi

/* Subround 41 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+72]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1836072691]
	mov ebp, eax
	rol edi, 13
	add edi, edx

/* Subround 42 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+88]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1836072691]
	mov ebp, edi
	rol edx, 5
	add edx, ecx

/* Subround 43 */
	xor ebp, -1
	or ebp, edx
	mov esi, [esp+48]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+1836072691]
	mov ebp, edx
	rol ecx, 14
	add ecx, ebx

/* Subround 44 */
	xor ebp, -1
	or ebp, ecx
	mov esi, [esp+80]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+1836072691]
	mov ebp, ecx
	rol ebx, 13
	add ebx, eax

/* Subround 45 */
	xor ebp, -1
	or ebp, ebx
	mov esi, [esp+40]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+1836072691]
	mov ebp, ebx
	rol eax, 13
	add eax, edi

/* Subround 46 */
	xor ebp, -1
	or ebp, eax
	mov esi, [esp+56]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+1836072691]
	mov ebp, eax
	rol edi, 7
	add edi, edx

/* Subround 47 */
	xor ebp, -1
	or ebp, edi
	mov esi, [esp+92]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+1836072691]
	mov ebp, edi
	rol edx, 5
	add edx, ecx

/* Subround 48 */
	xor ebp, eax
	and ebp, edx
	mov esi, [esp+72]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+2053994217]
	mov ebp, edx
	rol ecx, 15
	add ecx, ebx

/* Subround 49 */
	xor ebp, edi
	and ebp, ecx
	mov esi, [esp+64]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+2053994217]
	mov ebp, ecx
	rol ebx, 5
	add ebx, eax

/* Subround 50 */
	xor ebp, edx
	and ebp, ebx
	mov esi, [esp+56]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+2053994217]
	mov ebp, ebx
	rol eax, 8
	add eax, edi

/* Subround 51 */
	xor ebp, ecx
	and ebp, eax
	mov esi, [esp+44]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+2053994217]
	mov ebp, eax
	rol edi, 11
	add edi, edx

/* Subround 52 */
	xor ebp, ebx
	and ebp, edi
	mov esi, [esp+52]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+2053994217]
	mov ebp, edi
	rol edx, 14
	add edx, ecx

/* Subround 53 */
	xor ebp, eax
	and ebp, edx
	mov esi, [esp+84]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+2053994217]
	mov ebp, edx
	rol ecx, 14
	add ecx, ebx

/* Subround 54 */
	xor ebp, edi
	and ebp, ecx
	mov esi, [esp+100]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+2053994217]
	mov ebp, ecx
	rol ebx, 6
	add ebx, eax

/* Subround 55 */
	xor ebp, edx
	and ebp, ebx
	mov esi, [esp+40]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+2053994217]
	mov ebp, ebx
	rol eax, 14
	add eax, edi

/* Subround 56 */
	xor ebp, ecx
	and ebp, eax
	mov esi, [esp+60]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+2053994217]
	mov ebp, eax
	rol edi, 6
	add edi, edx

/* Subround 57 */
	xor ebp, ebx
	and ebp, edi
	mov esi, [esp+88]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+2053994217]
	mov ebp, edi
	rol edx, 9
	add edx, ecx

/* Subround 58 */
	xor ebp, eax
	and ebp, edx
	mov esi, [esp+48]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+2053994217]
	mov ebp, edx
	rol ecx, 12
	add ecx, ebx

/* Subround 59 */
	xor ebp, edi
	and ebp, ecx
	mov esi, [esp+92]
	xor ebp, edi
	add ebx, esi
	rol edx, 10
	lea ebx, [ebx+ebp+2053994217]
	mov ebp, ecx
	rol ebx, 9
	add ebx, eax

/* Subround 60 */
	xor ebp, edx
	and ebp, ebx
	mov esi, [esp+76]
	xor ebp, edx
	add eax, esi
	rol ecx, 10
	lea eax, [eax+ebp+2053994217]
	mov ebp, ebx
	rol eax, 12
	add eax, edi

/* Subround 61 */
	xor ebp, ecx
	and ebp, eax
	mov esi, [esp+68]
	xor ebp, ecx
	add edi, esi
	rol ebx, 10
	lea edi, [edi+ebp+2053994217]
	mov ebp, eax
	rol edi, 5
	add edi, edx

/* Subround 62 */
	xor ebp, ebx
	and ebp, edi
	mov esi, [esp+80]
	xor ebp, ebx
	add edx, esi
	rol eax, 10
	lea edx, [edx+ebp+2053994217]
	mov ebp, edi
	rol edx, 15
	add edx, ecx

/* Subround 63 */
	xor ebp, eax
	and ebp, edx
	mov esi, [esp+96]
	xor ebp, eax
	add ecx, esi
	rol edi, 10
	lea ecx, [ecx+ebp+2053994217]
	mov ebp, edx
	rol ecx, 8
	add ecx, ebx

/* Subround 64 */
	xor ebp, edi
	add ebx, [esp+88]
	xor ebp, ecx
	rol edx, 10
	add ebx, ebp
	mov ebp, ecx
	rol ebx, 8
	add ebx, eax

/* Subround 65 */
	xor ebp, edx
	add eax, [esp+100]
	xor ebp, ebx
	rol ecx, 10
	add eax, ebp
	mov ebp, ebx
	rol eax, 5
	add eax, edi

/* Subround 66 */
	xor ebp, ecx
	add edi, [esp+80]
	xor ebp, eax
	rol ebx, 10
	add edi, ebp
	mov ebp, eax
	rol edi, 12
	add edi, edx

/* Subround 67 */
	xor ebp, ebx
	add edx, [esp+56]
	xor ebp, edi
	rol eax, 10
	add edx, ebp
	mov ebp, edi
	rol edx, 9
	add edx, ecx

/* Subround 68 */
	xor ebp, eax
	add ecx, [esp+44]
	xor ebp, edx
	rol edi, 10
	add ecx, ebp
	mov ebp, edx
	rol ecx, 12
	add ecx, ebx

/* Subround 69 */
	xor ebp, edi
	add ebx, [esp+60]
	xor ebp, ecx
	rol edx, 10
	add ebx, ebp
	mov ebp, ecx
	rol ebx, 5
	add ebx, eax

/* Subround 70 */
	xor ebp, edx
	add eax, [esp+72]
	xor ebp, ebx
	rol ecx, 10
	add eax, ebp
	mov ebp, ebx
	rol eax, 14
	add eax, edi

/* Subround 71 */
	xor ebp, ecx
	add edi, [esp+68]
	xor ebp, eax
	rol ebx, 10
	add edi, ebp
	mov ebp, eax
	rol edi, 6
	add edi, edx

/* Subround 72 */
	xor ebp, ebx
	add edx, [esp+64]
	xor ebp, edi
	rol eax, 10
	add edx, ebp
	mov ebp, edi
	rol edx, 8
	add edx, ecx

/* Subround 73 */
	xor ebp, eax
	add ecx, [esp+48]
	xor ebp, edx
	rol edi, 10
	add ecx, ebp
	mov ebp, edx
	rol ecx, 13
	add ecx, ebx

/* Subround 74 */
	xor ebp, edi
	add ebx, [esp+92]
	xor ebp, ecx
	rol edx, 10
	add ebx, ebp
	mov ebp, ecx
	rol ebx, 6
	add ebx, eax

/* Subround 75 */
	xor ebp, edx
	add eax, [esp+96]
	xor ebp, ebx
	rol ecx, 10
	add eax, ebp
	mov ebp, ebx
	rol eax, 5
	add eax, edi

/* Subround 76 */
	xor ebp, ecx
	add edi, [esp+40]
	xor ebp, eax
	rol ebx, 10
	add edi, ebp
	mov ebp, eax
	rol edi, 15
	add edi, edx

/* Subround 77 */
	xor ebp, ebx
	add edx, [esp+52]
	xor ebp, edi
	rol eax, 10
	add edx, ebp
	mov ebp, edi
	rol edx, 13
	add edx, ecx

/* Subround 78 */
	xor ebp, eax
	add ecx, [esp+76]
	xor ebp, edx
	rol edi, 10
	add ecx, ebp
	mov ebp, edx
	rol ecx, 11
	add ecx, ebx

/* Subround 79 */
	xor ebp, edi
	add ebx, [esp+84]
	xor ebp, ecx
	rol edx, 10
	add ebx, ebp
	mov ebp, ecx
	rol ebx, 11
	add ebx, eax

/* combine */
	push ecx
	mov esi, [esp+12]
	mov ecx, [esp+20]
	add ecx, eax
	mov eax, esi
	mov esi, [esp+28]
	mov ebp, [esp+36]
	add eax, esi
	add ecx, ebp
	add eax, edx
	mov ebp, [esp+4]
	mov edx, ebx
	mov esi, [esp+16]
	mov ebx, edi
	add edx, ebp
	add ebx, esi
	mov ebp, [esp+32]
	add ebx, ebp
	mov ebp, [esp+40]
	add edx, ebp
	mov edi, [esp]
	add edi, [esp+8]
	mov ebp, [esp+24]
	add edi, ebp
	add esp, 44
	mov esi, [esp+84]
	add esp, 64
	mov [esi], eax
	mov [esi+4], ebx
	mov [esi+8], ecx
	mov [esi+12], edx
	mov [esi+16], edi

	pop ebx
	pop edi
	pop esi
	pop ebp

	ret
  }
}
