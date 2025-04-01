#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XSimpleCrypt.h"

XSimpleCrypt::XSimpleCrypt(void) {
}

XSimpleCrypt::~XSimpleCrypt(void) {
}

//---------------------------------------------------------------------------
// Methode 1 : Simple et reversible sans password
//---------------------------------------------------------------------------
UnicodeString __fastcall XSimpleCrypt::Encode(UnicodeString pw) {
	UnicodeString epw = pw;
	for ( int i = 1; i <= pw.Length(); i++ ) {
		if      (pw[i] >= 'a' && pw[i] <= 'z') epw[i] = 'z' - (pw[i] - 'a');
		else if (pw[i] >= 'A' && pw[i] <= 'Z') epw[i] = 'Z' - (pw[i] - 'A');
		else if (pw[i] >= '0' && pw[i] <= '9') epw[i] = '9' - (pw[i] - '0');
		else epw[i] = pw[i];
	}
	return epw;
}

//---------------------------------------------------------------------------
// Methode 2 : Simple non reversible sans password
//---------------------------------------------------------------------------
char          __fastcall XSimpleCrypt::RandomChar(void) {
	return static_cast<char>(32 + (std::rand() % (126 - 32 + 1)));
}

UnicodeString __fastcall XSimpleCrypt::Encrypt(UnicodeString pw) {
	UnicodeString epw = Encode(pw);
	return UnicodeString(RandomChar()) + epw + UnicodeString(RandomChar()) + UnicodeString(RandomChar());
}

UnicodeString __fastcall XSimpleCrypt::Decrypt(UnicodeString pw) {
	UnicodeString epw = Encode(pw);
	return epw.SubString(2,epw.Length()-3);
}

