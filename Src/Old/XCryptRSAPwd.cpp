#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XCryptRSAPwd.h"

XCryptRSAPwd::XCryptRSAPwd(void) {
	RSAKey    = new XRSAKey();
	PPassword = L"";
	hProv     = NULL;
	hKey      = NULL;
	hHash     = NULL;
	buffer    = NULL;
	PReady    = false;
}

XCryptRSAPwd::~XCryptRSAPwd(void) {
	delete RSAKey;
	ClearKey();
}

//---------------------------------------------------------------------------
// Methode : WinCrypt - RSA AES Password
//---------------------------------------------------------------------------
std::string __fastcall XCryptRSAPwd::UStringToStdString(const UnicodeString& ustr) {
    AnsiString ansi(ustr);
    return std::string(ansi.c_str());
}

void __fastcall XCryptRSAPwd::ClearKey(void) {
	if (hKey  != NULL) { CryptDestroyKey(hKey);         hKey   = NULL; }
	if (hProv != NULL) { CryptReleaseContext(hProv, 0); hProv  = NULL; }
	if (hHash != NULL) { CryptDestroyHash(hHash);       hHash  = NULL; }
	if (buffer!= NULL) { delete[] buffer;               buffer = NULL; }

	PPassword = L"";
	PReady = false;
}

//---------------------------------------------------------------------------
// Crypte / Encrypte une String - RSA AES
//---------------------------------------------------------------------------
bool __fastcall XCryptRSAPwd::SetPassword(UnicodeString password) {
	ClearKey();
	PPassword = password;
	std::string pwd = UStringToStdString(password);

	// Acquérir un contexte cryptographique
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { ClearKey(); return false; }

	// Créer un hash du mot de passe
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { ClearKey(); return false;  }

	// Ajouter le mot de passe au hash
	if (!CryptHashData(hHash, (BYTE*)pwd.c_str(), pwd.length(), 0)) { ClearKey(); return false; }

	// Dériver une clé AES à partir du hash
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) { ClearKey(); return false; }

	PReady = true;
	return true;
}

UnicodeString __fastcall XCryptRSAPwd::EncryptString(UnicodeString str) {
	if (RSAKey == NULL) return L"Erreur: RSAKey non initialisée";
	if (hKey == NULL) return L"Erreur: Clé Publique non initialisée";
	return RSAKey->EncryptString(str,hKey);
}

UnicodeString __fastcall XCryptRSAPwd::DecryptString(UnicodeString str) {
	if (RSAKey == NULL) return L"Erreur: RSAKey non initialisée";
	if (hKey == NULL) return L"Erreur: Clé Privée non initialisée";
	return RSAKey->DecryptString(str,hKey);
}

//---------------------------------------------------------------------------
// Crypte / Decrypte une un fichier - RSA AES par Password (sans clé)
//---------------------------------------------------------------------------
bool __fastcall XCryptRSAPwd::EncryptFile(UnicodeString infile, UnicodeString outfile) {
	if (RSAKey == NULL) return false;
	if (hKey == NULL) return false;
	return RSAKey->EncryptFile(infile,outfile,hKey);
}

bool __fastcall XCryptRSAPwd::DecryptFile(UnicodeString infile, UnicodeString outfile) {
	if (RSAKey == NULL) return false;
	if (hKey == NULL) return false;
	return RSAKey->DecryptFile(infile,outfile,hKey);
}

