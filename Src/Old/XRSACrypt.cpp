#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XRSACrypt.h"

XRSACrypt::XRSACrypt(void) {
}

XRSACrypt::~XRSACrypt(void) {
}

std::string __fastcall XRSACrypt::UnicodeToString(const UnicodeString& ustr) {
	AnsiString ansi(ustr);
	return std::string(ansi.c_str());
}


//---------------------------------------------------------------------------
// Cryptage / Decryptage String
//---------------------------------------------------------------------------

UnicodeString __fastcall XRSACrypt::EncryptString(UnicodeString str, HCRYPTKEY key) {
	UnicodeString result;
	BYTE *buffer = NULL;

	// Vérifier que la clé est valide
	if (key == NULL) return L"Erreur: Clé de chiffrement invalide";

	try {
		// Convertir les UnicodeString en std::string
		std::string dataToEncrypt = UnicodeToString(str);

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

UnicodeString __fastcall XRSACrypt::DecryptString(UnicodeString str, HCRYPTKEY key) {
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
bool __fastcall XRSACrypt::EncryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key) {
	bool success = false;
//	BYTE *buffer = NULL;
//
//	// Convertir les UnicodeString en std::string
//	std::string inputFile = UnicodeToString(infile);
//	std::string outputFile = UnicodeToString(outfile);
//
//	// Ouvrir les fichiers en mode binaire
//	std::ifstream inFile(inputFile.c_str(), std::ios::binary);
//	std::ofstream outFile(outputFile.c_str(), std::ios::binary);
//
//	if (!inFile || !outFile) return false;
//
//	// Traiter le fichier par blocs
//	const DWORD BUFFER_SIZE = 8192; // Taille de buffer plus grande
//	buffer = new BYTE[BUFFER_SIZE];
//	if (!buffer) goto Cleanup;
//
//	try {
//		// Déterminer la taille du fichier pour savoir quand on atteint la fin
//		inFile.seekg(0, std::ios::end);
//		std::streamsize fileSize = inFile.tellg();
//		inFile.seekg(0, std::ios::beg);
//
//		// Vérifier si le fichier est vide
//		if (fileSize == 0) {
//			// Créer un fichier vide et considérer l'opération comme réussie
//			success = true;
//			goto Cleanup;
//		}
//
//		std::streamsize totalBytesRead = 0;
//
//		// Lire et chiffrer les données par blocs
//		while (totalBytesRead < fileSize) {
//			// Lire un bloc de données
//			DWORD blockSize = (DWORD)std::min((std::streamsize)(BUFFER_SIZE - 1024), fileSize - totalBytesRead);
//			inFile.read((char*)buffer, blockSize);
//			DWORD bytesRead = (DWORD)inFile.gcount();
//
//			if (bytesRead == 0) break;
//
//			totalBytesRead += bytesRead;
//			bool isFinalBlock = (totalBytesRead >= fileSize);
//
//			// Chiffrer le bloc
//			DWORD encryptedSize = bytesRead;
//			DWORD dwBufLen = BUFFER_SIZE;
//
//			// Vérifier que la clé est valide
//			if (key == NULL) {
//				throw std::runtime_error("Clé de chiffrement invalide");
//			}
//
//			// Tenter de chiffrer avec gestion d'erreur détaillée
//			if (!CryptEncrypt(key, 0, isFinalBlock, 0, buffer, &encryptedSize, dwBufLen)) {
//				DWORD lastError = GetLastError();
//				char errorMsg[256];
//				sprintf(errorMsg, "Erreur lors du chiffrement: %lu", lastError);
//				throw std::runtime_error(errorMsg);
//			}
//
//			// Écrire le bloc chiffré
//			outFile.write((char*)buffer, encryptedSize);
//		}
//
//		success = true;
//	}
//	catch (const std::exception& e) {
//		// Journaliser l'erreur pour le débogage
//		std::string errorMsg = e.what();
//		success = false;
//	}
//
//	Cleanup:
//	if (buffer) delete[] buffer;
//	inFile.close();
//	outFile.close();

	return success;
}

bool __fastcall XRSACrypt::DecryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key) {
	bool success = false;
//	BYTE *buffer = NULL;
//
//	// Convertir les UnicodeString en std::string
//	std::string inputFile  = UnicodeToString(infile);
//	std::string outputFile = UnicodeToString(outfile);
//
//	// Ouvrir les fichiers en mode binaire
//	std::ifstream inFile(inputFile.c_str(), std::ios::binary);
//	std::ofstream outFile(outputFile.c_str(), std::ios::binary);
//
//	if (!inFile || !outFile) return false;
//
//	// Traiter le fichier par blocs
//	const DWORD BUFFER_SIZE = 8192; // Taille de buffer plus grande
//	buffer = new BYTE[BUFFER_SIZE];
//	if (!buffer) goto Cleanup;
//
//	try {
//		// Déterminer la taille du fichier pour savoir quand on atteint la fin
//		inFile.seekg(0, std::ios::end);
//		std::streamsize fileSize = inFile.tellg();
//		inFile.seekg(0, std::ios::beg);
//
//		// Vérifier si le fichier est vide
//		if (fileSize == 0) {
//			// Créer un fichier vide et considérer l'opération comme réussie
//			success = true;
//			goto Cleanup;
//		}
//
//		std::streamsize totalBytesRead = 0;
//
//		// Lire et déchiffrer les données par blocs
//		while (totalBytesRead < fileSize) {
//			// Lire un bloc de données chiffrées
//			DWORD blockSize = (DWORD)std::min((std::streamsize)BUFFER_SIZE, fileSize - totalBytesRead);
//			inFile.read((char*)buffer, blockSize);
//			DWORD bytesRead = (DWORD)inFile.gcount();
//
//			if (bytesRead == 0) break;
//
//			totalBytesRead += bytesRead;
//			bool isFinalBlock = (totalBytesRead >= fileSize);
//
//			// Déchiffrer le bloc
//			DWORD decryptedSize = bytesRead;
//			DWORD dwBufLen = BUFFER_SIZE;
//
//			// Vérifier que la clé est valide
//			if (key == NULL) {
//				throw std::runtime_error("Clé de déchiffrement invalide");
//			}
//
//			// Tenter de déchiffrer avec gestion d'erreur détaillée
//			if (!CryptDecrypt(key, 0, isFinalBlock, 0, buffer, &decryptedSize)) {
//				DWORD lastError = GetLastError();
//				char errorMsg[256];
//				sprintf(errorMsg, "Erreur lors du déchiffrement: %lu", lastError);
//				throw std::runtime_error(errorMsg);
//			}
//
//			// Écrire le bloc déchiffré
//			outFile.write((char*)buffer, decryptedSize);
//		}
//
//		success = true;
//	}
//	catch (const std::exception& e) {
//		// Journaliser l'erreur pour le débogage
//		std::string errorMsg = e.what();
//		success = false;
//	}
//
//Cleanup:
//	if (buffer) delete[] buffer;
//	inFile.close();
//	outFile.close();
	return success;
}


