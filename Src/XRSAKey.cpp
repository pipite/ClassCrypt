#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XRSAKey.h"

XRSAKey::XRSAKey(void) {
	hProv        = NULL;
	hPrivateKey  = NULL;
	hPublicKey   = NULL;
}

XRSAKey::~XRSAKey(void) {
	ClearKey();
}

//---------------------------------------------------------------------------
// Création, chargement, sauvegarde des paires de clés RSA
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

void __fastcall XRSAKey::ClearKey(void) {
	if (hPrivateKey != NULL)  CryptDestroyKey(hPrivateKey);
	if (hPublicKey != NULL)   CryptDestroyKey(hPublicKey);
	if (hProv != NULL)        CryptReleaseContext(hProv, 0);
	hPrivateKey = NULL;
	hPublicKey  = NULL;
	hProv       = NULL;
}

bool __fastcall XRSAKey::GenerateKeyPair(void) {
	// Acquérir le contexte cryptographique
	ClearKey();
	if ( !CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ) return false;

	// Générer une paire de clés RSA (2048 bits) exportable
	if ( !CryptGenKey(hProv, AT_KEYEXCHANGE, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &hPrivateKey) ) {
		ClearKey();
		return false;
	}
	// Extraire la clé publique depuis la clé privé
	if ( !ExtractPublicKey() ) {
		ClearKey();
		return false;
	}
	return true;
}

bool __fastcall XRSAKey::ExtractPublicKey(void) {
	DWORD publicKeySize = 0;
	BYTE* publicKeyBlob = nullptr;

    // 1️⃣ Obtenir la taille du BLOB de la clé publique
	if (!CryptExportKey(hPrivateKey, 0, PUBLICKEYBLOB, 0, NULL, &publicKeySize)) {
        return false;
    }

    // 2️⃣ Allouer un buffer en RAM pour stocker la clé publique
    publicKeyBlob = new BYTE[publicKeySize];

    // 3️⃣ Exporter la clé publique directement en RAM
	if (!CryptExportKey(hPrivateKey, 0, PUBLICKEYBLOB, 0, publicKeyBlob, &publicKeySize)) {
        delete[] publicKeyBlob;
        return false;
    }

    // 4️⃣ Importer la clé publique directement depuis la mémoire (pas de fichier)
	if (!CryptImportKey(hProv, publicKeyBlob, publicKeySize, 0, CRYPT_EXPORTABLE, &hPublicKey)) {
        delete[] publicKeyBlob;
        return false;
    }

    // ✅ Clé publique chargée en mémoire avec succès !
    delete[] publicKeyBlob;
    return true;
}

bool __fastcall XRSAKey::ImportKey(const std::string &filename) {
	BYTE *pbKeyBlob = nullptr;
	DWORD dwBlobLen = 0;
	bool success = false;

	ClearKey();

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;

	if (!LoadKeyFromFile(filename, &pbKeyBlob, dwBlobLen)) {
		ClearKey();
		return false;
	}

	if (IsPublicKey(pbKeyBlob, dwBlobLen)) {
		if (CryptImportKey(hProv, pbKeyBlob, dwBlobLen, 0, 0, &hPublicKey)) {
			success = true;
		} else {
			ClearKey();
		}
	} else if (IsPrivateKey(pbKeyBlob, dwBlobLen)) {
		// Spécifier CRYPT_EXPORTABLE pour permettre l'exportation ultérieure de la clé privée
		if (CryptImportKey(hProv, pbKeyBlob, dwBlobLen, 0, CRYPT_EXPORTABLE, &hPrivateKey)) {
			if (ExtractPublicKey()) {
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

	delete[] pbKeyBlob;
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


