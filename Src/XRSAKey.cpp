#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XRSAKey.h"

XRSAKey::XRSAKey(void) {
	AESCrypt      = new XAESCrypt();
	hProv         = NULL;
	hPrivateKey   = NULL;
	hPublicKey    = NULL;
	PPublicReady  = false;
	PPrivateReady = false;
}

XRSAKey::~XRSAKey(void) {
	ClearKey();
    delete AESCrypt;
}

std::string __fastcall XRSAKey::UnicodeToString(const UnicodeString& ustr) {
	AnsiString ansi(ustr);
	return std::string(ansi.c_str());
}


void __fastcall XRSAKey::ClearKey(void) {
	if (hPrivateKey != NULL)  CryptDestroyKey(hPrivateKey);
	if (hPublicKey != NULL)   CryptDestroyKey(hPublicKey);
	if (hProv != NULL)        CryptReleaseContext(hProv, 0);
	hPrivateKey   = NULL;
	hPublicKey    = NULL;
	hProv         = NULL;
	PPublicReady  = false;
	PPrivateReady = false;
}

//---------------------------------------------------------------------------
// Load/Save des clés
//---------------------------------------------------------------------------
bool __fastcall XRSAKey::LoadKeyFromFile(const std::string &filename, BYTE **buffer, DWORD &length) {
	std::ifstream file(filename, std::ios::binary | std::ios::ate);
	if (!file.is_open()) return false;

	length = file.tellg();
	file.seekg(0, std::ios::beg);
	*buffer = new BYTE[length];
	file.read(reinterpret_cast<char*>(*buffer), length);
	file.close();
	return true;
}

bool __fastcall XRSAKey::SaveKeyToFile(const std::string &filename, BYTE *data, DWORD length) {
	std::ofstream file(filename, std::ios::binary);
	if (file.is_open()) {
		file.write((char*)data, length);
		file.close();
		return true;
	} else {
		return false;
	}
}

//---------------------------------------------------------------------------
// Verification validité des clés
//---------------------------------------------------------------------------
bool __fastcall XRSAKey::IsPrivateKey(BYTE* buffer, DWORD length) {
	if (length < sizeof(BLOBHEADER)) return false;
	BLOBHEADER* header = reinterpret_cast<BLOBHEADER*>(buffer);
	return (header->bType == PRIVATEKEYBLOB);  // Vérifie si c'est une clé privée
}

bool __fastcall XRSAKey::IsPublicKey(BYTE* buffer, DWORD length) {
	if (length < sizeof(BLOBHEADER)) return false;  // Vérifie la taille minimale
	BLOBHEADER* header = reinterpret_cast<BLOBHEADER*>(buffer);
	return (header->bType == PUBLICKEYBLOB);  // Vérifie si c'est une clé publique
}

bool __fastcall XRSAKey::IsValidPublicKey(void) {
	if (hPublicKey == NULL) { // || hPublicKey == INVALID_HANDLE_VALUE) {
		return false;
	}

	DWORD dwBlobLen = 0;

	// Vérification de la taille de la clé
	DWORD dwKeySize = 0;
	if (!CryptGetKeyParam(hPublicKey, KP_KEYLEN, (BYTE*)&dwKeySize, &dwBlobLen, 0)) {
		return false;
	}

	// Vérification de l'algorithme
	ALG_ID algid;
	if (!CryptGetKeyParam(hPublicKey, KP_ALGID, (BYTE*)&algid, &dwBlobLen, 0)) {
		return false;
	}

	// Test de chiffrement
	const BYTE testData[] = "Test";
	DWORD testDataLen = sizeof(testData);
	DWORD encryptedLen = testDataLen;
	BYTE* encryptedData = new BYTE[encryptedLen];

	memcpy(encryptedData, testData, testDataLen);
	BOOL encryptResult = CryptEncrypt(hPublicKey, 0, TRUE, 0, encryptedData, &testDataLen, encryptedLen);

	delete[] encryptedData;

	if (!encryptResult) {
		return false;
	}

	return true;
}

//---------------------------------------------------------------------------
// Extraction PublicKey from PrivateKey
//---------------------------------------------------------------------------

bool __fastcall XRSAKey::ExtractPublicKey(void) {
	BYTE *blob = nullptr;
	DWORD blobLen = 0;

	DWORD provParam;
	DWORD provParamSize = sizeof(DWORD);
	if (!CryptGetProvParam(hProv, PP_PROVTYPE, (BYTE*)&provParam, &provParamSize, 0)) {
		// Le provider n'est pas valide
		return false;
	}

	DWORD keySpec;
	BOOL isKeySet;
	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPrivateKey)) {
		// La clé privée n'est pas correctement configurée
		return false;
	}

	// 1️⃣ Obtenir la taille du BLOB de la clé publique
	if (!CryptExportKey(hPrivateKey, 0, PUBLICKEYBLOB, 0, NULL, &blobLen)) {
		// Le provider n'est pas valide
		return false;
	}

	// 2️⃣ Allouer un buffer en RAM pour stocker la clé publique
	blob = new BYTE[blobLen];

	// 3️⃣ Exporter la clé publique directement en RAM
	if (!CryptExportKey(hPrivateKey, 0, PUBLICKEYBLOB, 0, blob, &blobLen)) {
		delete[] blob;
		return false;
	}

	// 4️⃣ Importer la clé publique directement depuis la mémoire (pas de fichier)
	if (!CryptImportKey(hProv, blob, blobLen, 0, CRYPT_EXPORTABLE, &hPublicKey)) {
		delete[] blob;
		return false;
	}

	ALG_ID algid;
	DWORD algidSize = sizeof(ALG_ID);
	if (!CryptGetKeyParam(hPublicKey, KP_ALGID, (BYTE*)&algid, &algidSize, 0) || algid != CALG_RSA_KEYX) {
		delete[] blob;
		return false;
		// La clé n'a pas le bon algorithme
	}
	PPublicReady = true;

//	if (!IsValidPublicKey() ) {
//		PPublicReady = false;
//		return false;
//	}

	// ✅ Clé publique chargée en mémoire avec succès !
	delete[] blob;
	return true;
}

//---------------------------------------------------------------------------
// Création, chargement, sauvegarde des paires de clés RSA
//---------------------------------------------------------------------------

bool __fastcall XRSAKey::GenerateKeyPair(void) {
	// Acquérir le contexte cryptographique
	ClearKey();
	
	// Tenter d'acquérir un contexte cryptographique
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		// Si l'acquisition échoue, essayer de créer un nouveau conteneur
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET)) {
			return false;
		}
	}

	// Générer une paire de clés RSA (1024 bits) exportable
	// Note: RSA1024BIT_KEY est utilisé ici, mais pour une sécurité accrue,
	// envisager d'utiliser 2048 bits ou plus (RSA2048BIT_KEY)
	if (!CryptGenKey(hProv, AT_KEYEXCHANGE, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &hPrivateKey)) {
		DWORD lastError = GetLastError();
		ClearKey();
		return false;
	}

	// Vérifier que les clés sont valides
	if (hPrivateKey == NULL) {
		ClearKey();
		return false;
	}

	// Extraire la clé publique depuis la clé privée
	if (!ExtractPublicKey()) {
		ClearKey();
		return false;
	}

	PPrivateReady = true;

	return true;
}

bool __fastcall XRSAKey::ImportKey(const std::string &filename) {
	BYTE *blob    = nullptr;
	DWORD blobLen = 0;
	bool success  = false;

	ClearKey();

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;

	if (!LoadKeyFromFile(filename, &blob, blobLen)) {
		ClearKey();
		return false;
	}

	if (IsPublicKey(blob, blobLen)) {
		if (CryptImportKey(hProv, blob, blobLen, 0, 0, &hPublicKey)) {
			PPublicReady = true;
			success = true;
		} else {
			ClearKey();
		}
	} else if (IsPrivateKey(blob, blobLen)) {
		// Spécifier CRYPT_EXPORTABLE pour permettre l'exportation ultérieure de la clé privée
		if (CryptImportKey(hProv, blob, blobLen, 0, CRYPT_EXPORTABLE, &hPrivateKey)) {
			PPrivateReady = true;
			if (ExtractPublicKey()) {
				PPublicReady = true;
				success = true;
			} else {
				ClearKey();
			}
		} else {
			ClearKey();
		}
	} else {
		ClearKey();
	}

	delete[] blob;
	return success;
}

bool __fastcall XRSAKey::ExportPrivateKey(const std::string &filename) {
	BYTE* pbKeyBlob = nullptr;
	DWORD dwBlobLen = 0;
	bool success = false;

	// Exporter la clé privée au format PRIVATEKEYBLOB
	if (hPrivateKey == NULL) return false;
	
	// 1. Obtenir la taille nécessaire pour le blob de la clé privée
	if (!CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwBlobLen)) {
		return false;
	}
	
	// 2. Allouer un buffer de la taille appropriée
	pbKeyBlob = new BYTE[dwBlobLen];
	
	// 3. Exporter la clé privée
	if (CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, pbKeyBlob, &dwBlobLen)) {
		success = SaveKeyToFile(filename, pbKeyBlob, dwBlobLen);
	}
	
	// 4. Libérer la mémoire
	delete[] pbKeyBlob;
	return success;
}

bool __fastcall XRSAKey::ExportPublicKey(const std::string &filename) {
	BYTE* pbKeyBlob = nullptr;
	DWORD dwBlobLen = 0;
	bool success = false;

	// Exporter la clé publique au format PUBLICKEYBLOB
	if (hPublicKey == NULL) return false;
	
	// 1. Obtenir la taille nécessaire pour le blob de la clé publique
	if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
		return false;
	}
	
	// 2. Allouer un buffer de la taille appropriée
	pbKeyBlob = new BYTE[dwBlobLen];
	
	// 3. Exporter la clé publique
	if (CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen)) {
		success = SaveKeyToFile(filename, pbKeyBlob, dwBlobLen);
	}
	
	// 4. Libérer la mémoire
	delete[] pbKeyBlob;
	return success;
}

//---------------------------------------------------------------------------
// Cryptage / Decryptage String RSA
//---------------------------------------------------------------------------
UnicodeString __fastcall XRSAKey::EncryptString(const UnicodeString& str) {
//	if (PPublicReady) return RSACrypt->EncryptString(str,hPublicKey);
//	return L"Pas de clé publique disponible";
}

UnicodeString __fastcall XRSAKey::DecryptString(const UnicodeString& hexstr) {
//	if (PPrivateReady) return RSACrypt->DecryptString(hexstr,hPrivateKey);
//	return L"Pas de clé privée disponible";
}

//---------------------------------------------------------------------------
// Crypte / Decrypte une un fichier
//---------------------------------------------------------------------------
bool __fastcall XRSAKey::EncryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
//	if (PPublicReady) return RSACrypt->EncryptFile(infile,outfile,hPrivateKey);
//	return false;
}

bool __fastcall XRSAKey::DecryptFile(const UnicodeString& infile, const UnicodeString& outfile) {
//	if (PPrivateReady) return RSACrypt->DecryptFile(infile,outfile,hPrivateKey);
//	return false;
}

