#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XAESCrypt.h"

XAESCrypt::XAESCrypt(void) {
//	HCRYPTPROV hTempProv = NULL;
}

XAESCrypt::~XAESCrypt(void) {
//	if ( hTempProv != NULL ) CryptReleaseContext(hTempProv, 0);
}

//---------------------------------------------------------------------------
// Cryptage / Decryptage String - AES
//---------------------------------------------------------------------------
UnicodeString __fastcall XAESCrypt::EncryptString(UnicodeString str, HCRYPTKEY key) {
	try {
		std::vector<BYTE> buff = UnicodeToBuffer(str);
		std::vector<BYTE> encryptedBuffer = EncryptBuffer(buff, key);
		return BufferToHex(encryptedBuffer);
    }
    catch (const std::exception& e) {
        return UnicodeString(L"Erreur: ") + UnicodeString(e.what());
    }
}

UnicodeString __fastcall XAESCrypt::DecryptString(UnicodeString str, HCRYPTKEY key) {
    try {
		std::vector<BYTE> buff = HexToBuffer(str);
        std::vector<BYTE> decryptedBuffer = DecryptBuffer(buff, key);
		return BufferToUnicode(decryptedBuffer);
	}
    catch (const std::exception& e) {
		return UnicodeString(L"Erreur: ") + UnicodeString(e.what());
    }
}

//---------------------------------------------------------------------------
// Cryptage / Decryptage fichier - AES
//---------------------------------------------------------------------------
bool __fastcall XAESCrypt::EncryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key) {
	try {
		std::vector<BYTE> fileBuffer = FileToBuffer(infile);
		std::vector<BYTE> encryptedData = EncryptBuffer(fileBuffer, key);
		return BufferToFile(encryptedData, outfile);
    } catch (const std::exception& e) {
		//std::cerr << "Erreur: " << e.what() << std::endl;
        return false;
    }
}

bool __fastcall XAESCrypt::DecryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key) {
	try {
		std::vector<BYTE> fileBuffer = FileToBuffer(infile);
		std::vector<BYTE> decryptedData = DecryptBuffer(fileBuffer, key);
		return BufferToFile(decryptedData, outfile);
    } catch (const std::exception& e) {
		//std::cerr << "Erreur: " << e.what() << std::endl;
        return false;
    }
}

//---------------------------------------------------------------------------
// Cryptage / Decryptage Buffer
//---------------------------------------------------------------------------
std::vector<BYTE> __fastcall XAESCrypt::EncryptBuffer(const std::vector<BYTE>& data, HCRYPTKEY key) {
    if (key == NULL) {
        throw std::runtime_error("Clé de chiffrement invalide");
    }

    std::vector<BYTE> encryptedData;
    const DWORD BUFFER_SIZE = 8192;
    std::vector<BYTE> buffer(BUFFER_SIZE);

    std::streamsize totalBytesRead = 0;
    std::streamsize fileSize = data.size();

    while (totalBytesRead < fileSize) {
        DWORD blockSize = (DWORD)std::min((std::streamsize)(BUFFER_SIZE - 1024), fileSize - totalBytesRead);
        memcpy(buffer.data(), data.data() + totalBytesRead, blockSize);
        DWORD encryptedSize = blockSize;
        DWORD dwBufLen = BUFFER_SIZE;
        bool isFinalBlock = (totalBytesRead + blockSize >= fileSize);

        // Chiffrement du bloc
        if (!CryptEncrypt(key, 0, isFinalBlock, 0, buffer.data(), &encryptedSize, dwBufLen)) {
            throw std::runtime_error("Erreur lors du chiffrement: " + std::to_string(GetLastError()));
        }

        encryptedData.insert(encryptedData.end(), buffer.begin(), buffer.begin() + encryptedSize);
        totalBytesRead += blockSize;
    }

    return encryptedData;
}

std::vector<BYTE> __fastcall XAESCrypt::DecryptBuffer(const std::vector<BYTE>& encryptedData, HCRYPTKEY key) {
	if (key == NULL) {
        throw std::runtime_error("Erreur: Clé de déchiffrement invalide");
    }

    std::vector<BYTE> buffer = encryptedData;
    DWORD decryptedLen = buffer.size();

    if (!CryptDecrypt(key, 0, TRUE, 0, buffer.data(), &decryptedLen)) {
        throw std::runtime_error("Erreur lors du déchiffrement: " + std::to_string(GetLastError()));
    }

    buffer.resize(decryptedLen); // Ajuster la taille réelle après déchiffrement
    return buffer;
}

//---------------------------------------------------------------------------
// Import / Export Key WinCrypt HCRYPTKEY <> vector<BYTE>
//---------------------------------------------------------------------------
// Exporte une clé AES HCRYPTKEY en vector<BYTE>
std::vector<BYTE> __fastcall XAESCrypt::ExportAesKey(HCRYPTKEY hAesKey) {
    if (hAesKey == NULL) {
        throw std::runtime_error("Clé AES invalide");
    }

    // Obtenir la taille nécessaire pour le blob de la clé
    DWORD keyBlobLen = 0;
    if (!CryptExportKey(hAesKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keyBlobLen)) {
        throw std::runtime_error("Impossible de déterminer la taille de la clé AES: " + std::to_string(GetLastError()));
    }

    // Allouer un buffer pour la clé
    std::vector<BYTE> keyBlob(keyBlobLen);

	// Exporter la clé
    if (!CryptExportKey(hAesKey, 0, PLAINTEXTKEYBLOB, 0, keyBlob.data(), &keyBlobLen)) {
        throw std::runtime_error("Impossible d'exporter la clé AES: " + std::to_string(GetLastError()));
	}

	return keyBlob;
}

// Exporte une clé AES depuis un vecteur d'octets
bool __fastcall XAESCrypt::ImportAesKey(HCRYPTPROV &prov, HCRYPTKEY &key, const std::vector<BYTE>& keyBlob) {
	bool success = false;
	// Acquérir un contexte cryptographique pour AES
	if ( prov == NULL ) {
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
	}

	// Importer la clé AES
	if (!CryptImportKey(prov, keyBlob.data(), keyBlob.size(), 0, 0, &key)) return false;

	return true;
}

//---------------------------------------------------------------------------
// Generateur de clé AES HCRYPTKEY
//---------------------------------------------------------------------------
// Génère une clé AES
bool __fastcall XAESCrypt::NewRandomAesKey(HCRYPTPROV &prov, HCRYPTKEY &key) {
	// Acquérir un contexte cryptographique pour AES
	if ( prov == NULL ) {
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
	}

	// Générer une clé AES-256 aléatoire
	if (!CryptGenKey(prov, CALG_AES_256, CRYPT_EXPORTABLE, &key)) return false;
	return true;
}






/*

bool GenerateAESKey(const std::string& pwd, HCRYPTPROV& hProv, HCRYPTKEY& hKey, BYTE* salt) {
	// Acquérir un contexte cryptographique
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return false;
	}

	// Générer un sel aléatoire (128 bits)
	if (!CryptGenRandom(hProv, 16, salt)) {
		return false;
	}

	// Créer un hash SHA-256
	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return false;
	}

	// Ajouter le sel au hash
	if (!CryptHashData(hHash, salt, 16, 0)) {
		CryptDestroyHash(hHash);
		return false;
	}

	// Ajouter le mot de passe au hash SHA
	if (!CryptHashData(hHash, (BYTE*)pwd.c_str(), pwd.length(), 0)) {
		CryptDestroyHash(hHash);
		return false;
	}

	// Dériver une clé AES à partir du hash SHA
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		CryptDestroyHash(hHash);
		return false;
	}

	CryptDestroyHash(hHash);
	return true;
}

bool DecryptAES(const std::string& pwd, BYTE* encryptedData, DWORD encryptedSize, BYTE*& decryptedData, DWORD& decryptedSize) {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	BYTE salt[16];

	// Récupérer le sel depuis les 16 premiers octets du fichier chiffré
	memcpy(salt, encryptedData, 16);
	encryptedData += 16;
	encryptedSize -= 16;

	// Générer la clé avec le même sel
	if (!GenerateAESKey(pwd, hProv, hKey, salt)) {
		return false;
	}

	// Déchiffrer les données
	decryptedSize = encryptedSize;
	decryptedData = new BYTE[decryptedSize];
	memcpy(decryptedData, encryptedData, encryptedSize);

	if (!CryptDecrypt(hKey, 0, TRUE, 0, decryptedData, &decryptedSize)) {
		return false;
	}

	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
	return true;
}


*/
