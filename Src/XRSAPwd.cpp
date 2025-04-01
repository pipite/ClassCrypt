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
	buffer    = NULL;
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
	if (buffer!= NULL) { delete[] buffer;               buffer = NULL; }

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
//	if (PReady) return AESCrypt->EncryptString(str,hKey);
	return L"Pas de SecretKey disponible";
}

UnicodeString __fastcall XRSAPwd::DecryptString(UnicodeString str) {
//	if (PReady) return AESCrypt->DecryptString(str,hKey);
	return L"Pas de SecretKey disponible";
}

//---------------------------------------------------------------------------
// AES Crypte / Decrypte AES (symetrique) - fichier protégé par Password RSA (assymetrique)
//---------------------------------------------------------------------------
bool __fastcall XRSAPwd::EncryptFile(UnicodeString infile, UnicodeString outfile) {
	if ( !RSAKey->PublicReady ) return false;

	// Générer une clé AES aléatoire pour ce fichier
	BYTE aesKey[32]; // Clé AES 256 bits
	BYTE aesIV[16];  // Vecteur d'initialisation AES

	// Générer une clé et un IV aléatoires
	if (!CryptGenRandom(hProv, sizeof(aesKey), aesKey) ||
		!CryptGenRandom(hProv, sizeof(aesIV), aesIV)) {
		return false;
	}

//	// Configurer la clé AES pour le cryptage
//	AESCrypt->SetKey(aesKey, sizeof(aesKey));
//	AESCrypt->SetIV(aesIV, sizeof(aesIV));
//
//	// Préparer le buffer pour stocker la clé AES cryptée avec RSA
//	DWORD encryptedKeySize = 0;
//	BYTE keyBuffer[sizeof(aesKey) + sizeof(aesIV)];
//
//	// Copier la clé et l'IV dans le buffer
//	memcpy(keyBuffer, aesKey, sizeof(aesKey));
//	memcpy(keyBuffer + sizeof(aesKey), aesIV, sizeof(aesIV));
//
//	// Obtenir la taille nécessaire pour la clé cryptée
//	DWORD bufferSize = sizeof(keyBuffer);
//	BYTE* encryptedKeyBuffer = new BYTE[bufferSize * 2]; // Allouer plus d'espace pour être sûr
//	memcpy(encryptedKeyBuffer, keyBuffer, bufferSize);
//
//	// Crypter la clé AES avec la clé publique RSA
//	if (!CryptEncrypt(hPublicKey, 0, TRUE, 0, encryptedKeyBuffer, &bufferSize, bufferSize * 2)) {
//		delete[] encryptedKeyBuffer;
//		return false;
//	}
//
//	// Ouvrir le fichier source
//	std::ifstream sourceFile(UnicodeToString(infile), std::ios::binary);
//	if (!sourceFile.is_open()) {
//		delete[] encryptedKeyBuffer;
//		return false;
//	}
//
//	// Créer le fichier de sortie
//	std::ofstream destFile(UnicodeToString(outfile), std::ios::binary);
//	if (!outfile.is_open()) {
//		sourceFile.close();
//		delete[] encryptedKeyBuffer;
//		return false;
//	}
//
//	// Écrire la taille de la clé cryptée
//	destFile.write(reinterpret_cast<char*>(&bufferSize), sizeof(bufferSize));
//
//	// Écrire la clé AES cryptée
//	destFile.write(reinterpret_cast<char*>(encryptedKeyBuffer), bufferSize);
//
//	// Libérer la mémoire
//	delete[] encryptedKeyBuffer;
//
//	// Crypter le fichier avec AES
//	const int BUFFER_SIZE = 4096;
//	BYTE buffer[BUFFER_SIZE];
//	BYTE encryptedBuffer[BUFFER_SIZE];
//
//	while (sourceFile) {
//		sourceFile.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
//		std::streamsize bytesRead = sourceFile.gcount();
//
//		if (bytesRead > 0) {
//			// Crypter le bloc avec AES
//			memcpy(encryptedBuffer, buffer, bytesRead);
//			DWORD encryptedSize = static_cast<DWORD>(bytesRead);
//
//			if (AESCrypt->EncryptBlock(encryptedBuffer, encryptedSize)) {
//				// Écrire la taille du bloc crypté
//				destFile.write(reinterpret_cast<char*>(&encryptedSize), sizeof(encryptedSize));
//				// Écrire le bloc crypté
//				destFile.write(reinterpret_cast<char*>(encryptedBuffer), encryptedSize);
//			} else {
//				sourceFile.close();
//				destFile.close();
//				return false;
//			}
//		}
//	}
//
//	sourceFile.close();
//	destFile.close();
	return true;
}

bool __fastcall XRSAPwd::DecryptFile(UnicodeString infile, UnicodeString outfile) {
//	if (PReady) return AESCrypt->DecryptFile(infile,outfile,hKey);
	return false;
}

