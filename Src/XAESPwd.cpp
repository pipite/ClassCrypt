#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XAESPwd.h"

XAESPwd::XAESPwd(void) {
	AESCrypt  = new XAESCrypt();
	PPassword = L"";
	hProv     = NULL;
	hKey      = NULL;
	hHash     = NULL;
	buffer    = NULL;
	PReady    = false;
}

XAESPwd::~XAESPwd(void) {
	delete AESCrypt;
	ClearKey();
}

std::string __fastcall XAESPwd::UStringToStdString(const UnicodeString& ustr) {
	AnsiString ansi(ustr);
	return std::string(ansi.c_str());
}

//---------------------------------------------------------------------------
// WinCrypt - AES Password - AES Cryptage
//---------------------------------------------------------------------------

void __fastcall XAESPwd::ClearKey(void) {
	if (hKey  != NULL) { CryptDestroyKey(hKey);         hKey   = NULL; }
	if (hProv != NULL) { CryptReleaseContext(hProv, 0); hProv  = NULL; }
	if (hHash != NULL) { CryptDestroyHash(hHash);       hHash  = NULL; }
	if (buffer!= NULL) { delete[] buffer;               buffer = NULL; }

	PPassword = L"";
	PReady = false;
}

bool __fastcall XAESPwd::SetPassword(UnicodeString password) {
	ClearKey();
	PPassword = password;
	std::string pwd = UStringToStdString(password);

	// Acquérir un contexte cryptographique
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { ClearKey(); return false; }

	// Créer un hash
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { ClearKey(); return false;  }

	// Ajouter le mot de passe au hash
	if (!CryptHashData(hHash, (BYTE*)pwd.c_str(), pwd.length(), 0)) { ClearKey(); return false; }

	// Dériver une clé AES à partir du hash
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) { ClearKey(); return false; }

	PReady = true;
	return true;
}

//---------------------------------------------------------------------------
// Crypte / Encrypte AES (symetrique) - String protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
UnicodeString __fastcall XAESPwd::EncryptString(UnicodeString str) {
	if (PReady) return AESCrypt->EncryptString(str,hKey);
	return L"Pas de SecretKey disponible";
}

UnicodeString __fastcall XAESPwd::DecryptString(UnicodeString str) {
	if (PReady) return AESCrypt->DecryptString(str,hKey);
	return L"Pas de SecretKey disponible";
}

//---------------------------------------------------------------------------
// AES Crypte / Decrypte AES (symetrique) - fichier protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
bool __fastcall XAESPwd::EncryptFile(UnicodeString infile, UnicodeString outfile) {
	if (PReady) return AESCrypt->EncryptFile(infile,outfile,hKey);
	return false;
}

bool __fastcall XAESPwd::DecryptFile(UnicodeString infile, UnicodeString outfile) {
	if (PReady) return AESCrypt->DecryptFile(infile,outfile,hKey);
	return false;
}

