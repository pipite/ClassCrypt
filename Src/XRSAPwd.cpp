#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XRSAPwd.h"

XRSAPwd::XRSAPwd(void) {
	AESCrypt  = new XAESCrypt();
	RSAKey    = new XRSAKey();
	PPassword = L"";
	hProv     = NULL;
	hKey      = NULL;
	hHash     = NULL;
	PReady    = false;
}

XRSAPwd::~XRSAPwd(void) {
	delete AESCrypt;
	delete RSAKey;
	ClearKey();
}

std::string __fastcall XRSAPwd::UnicodeToString(const UnicodeString& ustr) {
	AnsiString ansi(ustr);
	return std::string(ansi.c_str());
}

//---------------------------------------------------------------------------
// WinCrypt - AES Password - AES Cryptage
//---------------------------------------------------------------------------

void __fastcall XRSAPwd::ClearKey(void) {
	if (hKey  != NULL) { CryptDestroyKey(hKey);         hKey   = NULL; }
	if (hProv != NULL) { CryptReleaseContext(hProv, 0); hProv  = NULL; }
	if (hHash != NULL) { CryptDestroyHash(hHash);       hHash  = NULL; }
	buffer.clear();

	PPassword = L"";
	PReady = false;
}

bool __fastcall XRSAPwd::SetPassword(UnicodeString password) {
	ClearKey();
	PPassword = password;
	std::string pwd = UnicodeToString(password);

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
UnicodeString __fastcall XRSAPwd::EncryptString(UnicodeString str) {
	return L"Pas de SecretKey disponible";
}

UnicodeString __fastcall XRSAPwd::DecryptString(UnicodeString str) {
	return L"Pas de SecretKey disponible";
}

//---------------------------------------------------------------------------
// AES Crypte / Decrypte AES (symetrique) - fichier protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
bool __fastcall XRSAPwd::EncryptFile(UnicodeString infile, UnicodeString outfile) {
	return true;
}

bool __fastcall XRSAPwd::DecryptFile(UnicodeString infile, UnicodeString outfile) {
	return false;
}

