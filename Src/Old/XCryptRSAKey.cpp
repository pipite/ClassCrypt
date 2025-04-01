#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XCryptRSAKey.h"

XCryptRSAKey::XCryptRSAKey(void) {
	RSAKey = NULL;
}

XCryptRSAKey::~XCryptRSAKey(void) {
	RSAKey = NULL;
}

void __fastcall XCryptRSAKey::SetRSAKey(XRSAKey *rsakey) {
	RSAKey = rsakey;
}

UnicodeString __fastcall XCryptRSAKey::EncryptString(const UnicodeString& input) {
	if (RSAKey == NULL) return L"Erreur: RSAKey non initialisée";
	if (RSAKey->PublicKey == NULL) return L"Erreur: Clé Publique non initialisée";
	return RSAKey->EncryptString(input,RSAKey->PublicKey);
}

UnicodeString __fastcall XCryptRSAKey::DecryptString(const UnicodeString& hexInput) {
	if (RSAKey == NULL) return L"Erreur: RSAKey non initialisée";
	if (RSAKey->PrivateKey == NULL) return L"Erreur: Clé Privée non initialisée";
	return RSAKey->DecryptString(hexInput,RSAKey->PrivateKey);
}

//---------------------------------------------------------------------------
// Crypte / Decrypte une un fichier - RSA AES par Password (sans clé)
//---------------------------------------------------------------------------
bool __fastcall XCryptRSAKey::EncryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
	if (RSAKey == NULL) return false;
	if (RSAKey->PublicKey == NULL) return false;
	return RSAKey->EncryptFile(infile,outfile,RSAKey->PublicKey);
}

bool __fastcall XCryptRSAKey::DecryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
	if (RSAKey == NULL) return false;
	if (RSAKey->PrivateKey == NULL) return false;
	return RSAKey->DecryptFile(infile,outfile,RSAKey->PrivateKey);
}

