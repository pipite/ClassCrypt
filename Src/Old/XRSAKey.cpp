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

std::string __fastcall XRSAKey::UStringToStdString(const UnicodeString& ustr) {
    AnsiString ansi(ustr);
    return std::string(ansi.c_str());
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
	
	// Extraire la clé publique depuis la clé privée
	if (!ExtractPublicKey()) {
		ClearKey();
		return false;
	}
	
	// Vérifier que les clés sont valides
	if (hPrivateKey == NULL || hPublicKey == NULL) {
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

//---------------------------------------------------------------------------
// Cryptage / Decryptage String
//---------------------------------------------------------------------------

UnicodeString __fastcall XRSAKey::EncryptString(UnicodeString str, HCRYPTKEY key) {
	UnicodeString result;
	BYTE *buffer = NULL;

	// Vérifier que la clé est valide
	if (key == NULL) return L"Erreur: Clé de chiffrement invalide";

	try {
		// Convertir les UnicodeString en std::string
		std::string dataToEncrypt = UStringToStdString(str);

		// Allouer un buffer pour les données chiffrées (taille originale + marge pour le padding)
		DWORD dataLen = dataToEncrypt.length();
		DWORD bufferLen = dataLen + 1024; // Marge pour le padding
		buffer = new BYTE[bufferLen];
		if (!buffer) return L"Erreur: Allocation mémoire échouée";

		// Copier les données dans le buffer
		memcpy(buffer, dataToEncrypt.c_str(), dataLen);

		// Chiffrer les données
		DWORD encryptedLen = dataLen;
		if (!CryptEncrypt(key, 0, TRUE, 0, buffer, &encryptedLen, bufferLen)) {
			DWORD lastError = GetLastError();
			delete[] buffer;
			wchar_t errorMsg[256];
			swprintf(errorMsg, 256, L"Erreur lors du chiffrement: %lu", lastError);
			return UnicodeString(errorMsg);
		}

		// Convertir les données chiffrées en hexadécimal
		for (DWORD i = 0; i < encryptedLen; i++) {
			wchar_t hex[3];
			swprintf(hex, 3, L"%02X", buffer[i]);
			result += UnicodeString(hex);
		}
	}
	catch (const std::exception&) {
		result = L"Erreur: Exception lors du chiffrement";
	}

	if (buffer) delete[] buffer;
	return result;
}

UnicodeString __fastcall XRSAKey::DecryptString(UnicodeString str, HCRYPTKEY key) {
	UnicodeString result;
	BYTE *buffer = NULL;

	// Vérifier que la clé est valide
	if (key == NULL) return L"Erreur: Clé de déchiffrement invalide";

	try {
		// Convertir la chaîne hexadécimale en données binaires
		int strLen = str.Length();
		if (strLen % 2 != 0) return L"Erreur: Format hexadécimal invalide"; // La chaîne hexadécimale doit avoir une longueur paire

		DWORD dataLen = strLen / 2;
		buffer = new BYTE[dataLen + 1]; // +1 pour le terminateur nul
		if (!buffer) return L"Erreur: Allocation mémoire échouée";

		// Convertir chaque paire de caractères hexadécimaux en octet
		for (int i = 1; i <= strLen; i += 2) {
			// UnicodeString est indexé à partir de 1, pas de 0
			if (i+1 > strLen) break; // Sécurité
			wchar_t hexByte[3] = {str[i], str[i+1], 0};
			int value;
			swscanf(hexByte, L"%x", &value);
			buffer[(i-1)/2] = (BYTE)value;
		}

		// Déchiffrer les données
		DWORD decryptedLen = dataLen;
		if (!CryptDecrypt(key, 0, TRUE, 0, buffer, &decryptedLen)) {
			DWORD lastError = GetLastError();
			delete[] buffer;
			wchar_t errorMsg[256];
			swprintf(errorMsg, 256, L"Erreur lors du déchiffrement: %lu", lastError);
			return UnicodeString(errorMsg);
		}

		// Convertir les données déchiffrées en UnicodeString
		buffer[decryptedLen] = 0; // Ajouter un terminateur nul
		result = UnicodeString((char*)buffer);
	}
	catch (const std::exception&) {
		result = L"Erreur: Exception lors du déchiffrement";
	}

	if (buffer) delete[] buffer;
	return result;
}

//---------------------------------------------------------------------------
// Crypte / Decrypte une un fichier - RSA AES
//---------------------------------------------------------------------------
bool __fastcall XRSAKey::EncryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key) {
	bool success = false;
	BYTE *buffer = NULL;

	// Convertir les UnicodeString en std::string
	std::string inputFile = UStringToStdString(infile);
	std::string outputFile = UStringToStdString(outfile);

	// Ouvrir les fichiers en mode binaire
	std::ifstream inFile(inputFile.c_str(), std::ios::binary);
	std::ofstream outFile(outputFile.c_str(), std::ios::binary);

	if (!inFile || !outFile) return false;

	// Traiter le fichier par blocs
	const DWORD BUFFER_SIZE = 8192; // Taille de buffer plus grande
	buffer = new BYTE[BUFFER_SIZE];
	if (!buffer) goto Cleanup;

	try {
		// Déterminer la taille du fichier pour savoir quand on atteint la fin
		inFile.seekg(0, std::ios::end);
		std::streamsize fileSize = inFile.tellg();
		inFile.seekg(0, std::ios::beg);

		// Vérifier si le fichier est vide
		if (fileSize == 0) {
			// Créer un fichier vide et considérer l'opération comme réussie
			success = true;
			goto Cleanup;
		}

		std::streamsize totalBytesRead = 0;

		// Lire et chiffrer les données par blocs
		while (totalBytesRead < fileSize) {
			// Lire un bloc de données
			DWORD blockSize = (DWORD)std::min((std::streamsize)(BUFFER_SIZE - 1024), fileSize - totalBytesRead);
			inFile.read((char*)buffer, blockSize);
			DWORD bytesRead = (DWORD)inFile.gcount();

			if (bytesRead == 0) break;

			totalBytesRead += bytesRead;
			bool isFinalBlock = (totalBytesRead >= fileSize);

			// Chiffrer le bloc
			DWORD encryptedSize = bytesRead;
			DWORD dwBufLen = BUFFER_SIZE;
			
			// Vérifier que la clé est valide
			if (key == NULL) {
				throw std::runtime_error("Clé de chiffrement invalide");
			}
			
			// Tenter de chiffrer avec gestion d'erreur détaillée
			if (!CryptEncrypt(key, 0, isFinalBlock, 0, buffer, &encryptedSize, dwBufLen)) {
				DWORD lastError = GetLastError();
				char errorMsg[256];
				sprintf(errorMsg, "Erreur lors du chiffrement: %lu", lastError);
				throw std::runtime_error(errorMsg);
			}

			// Écrire le bloc chiffré
			outFile.write((char*)buffer, encryptedSize);
		}

		success = true;
	}
	catch (const std::exception& e) {
		// Journaliser l'erreur pour le débogage
		std::string errorMsg = e.what();
		success = false;
	}

	Cleanup:
	if (buffer) delete[] buffer;
	inFile.close();
	outFile.close();

	return success;
}

bool __fastcall XRSAKey::DecryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key) {
	bool success = false;
	BYTE *buffer = NULL;

	// Convertir les UnicodeString en std::string
	std::string inputFile  = UStringToStdString(infile);
	std::string outputFile = UStringToStdString(outfile);

	// Ouvrir les fichiers en mode binaire
	std::ifstream inFile(inputFile.c_str(), std::ios::binary);
	std::ofstream outFile(outputFile.c_str(), std::ios::binary);

	if (!inFile || !outFile) return false;

	// Traiter le fichier par blocs
	const DWORD BUFFER_SIZE = 8192; // Taille de buffer plus grande
	buffer = new BYTE[BUFFER_SIZE];
	if (!buffer) goto Cleanup;

	try {
		// Déterminer la taille du fichier pour savoir quand on atteint la fin
		inFile.seekg(0, std::ios::end);
		std::streamsize fileSize = inFile.tellg();
		inFile.seekg(0, std::ios::beg);

		// Vérifier si le fichier est vide
		if (fileSize == 0) {
			// Créer un fichier vide et considérer l'opération comme réussie
			success = true;
			goto Cleanup;
		}

		std::streamsize totalBytesRead = 0;

		// Lire et déchiffrer les données par blocs
		while (totalBytesRead < fileSize) {
			// Lire un bloc de données chiffrées
			DWORD blockSize = (DWORD)std::min((std::streamsize)BUFFER_SIZE, fileSize - totalBytesRead);
			inFile.read((char*)buffer, blockSize);
			DWORD bytesRead = (DWORD)inFile.gcount();

			if (bytesRead == 0) break;

			totalBytesRead += bytesRead;
			bool isFinalBlock = (totalBytesRead >= fileSize);

			// Déchiffrer le bloc
			DWORD decryptedSize = bytesRead;
			DWORD dwBufLen = BUFFER_SIZE;
			
			// Vérifier que la clé est valide
			if (key == NULL) {
				throw std::runtime_error("Clé de déchiffrement invalide");
			}
			
			// Tenter de déchiffrer avec gestion d'erreur détaillée
			if (!CryptDecrypt(key, 0, isFinalBlock, 0, buffer, &decryptedSize)) {
				DWORD lastError = GetLastError();
				char errorMsg[256];
				sprintf(errorMsg, "Erreur lors du déchiffrement: %lu", lastError);
				throw std::runtime_error(errorMsg);
			}

			// Écrire le bloc déchiffré
			outFile.write((char*)buffer, decryptedSize);
		}

		success = true;
	}
	catch (const std::exception& e) {
		// Journaliser l'erreur pour le débogage
		std::string errorMsg = e.what();
		success = false;
	}

Cleanup:
	if (buffer) delete[] buffer;
	inFile.close();
	outFile.close();
	return success;
}


