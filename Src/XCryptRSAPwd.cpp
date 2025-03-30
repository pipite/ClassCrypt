#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XCryptRSAPwd.h"

XCryptRSAPwd::XCryptRSAPwd(void) {
	PPassword = L"";
	hProv    = NULL;
	hKey     = NULL;
	hHash    = NULL;
	buffer   = NULL;
	PReady   = false;
}

XCryptRSAPwd::~XCryptRSAPwd(void) {
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
	UnicodeString result;

	// Convertir les UnicodeString en std::string
	std::string dataToEncrypt = UStringToStdString(str);

    // Allouer un buffer pour les données chiffrées (taille originale + marge pour le padding)
    DWORD dataLen = dataToEncrypt.length();
    DWORD bufferLen = dataLen + 1024; // Marge pour le padding
	buffer = new BYTE[bufferLen];

    if (!buffer) return L"";

	// Copier les données dans le buffer
    memcpy(buffer, dataToEncrypt.c_str(), dataLen);

	// Chiffrer les données
    DWORD encryptedLen = dataLen;
	if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer, &encryptedLen, bufferLen)) { return L"";  }

    // Convertir les données chiffrées en hexadécimal
    for (DWORD i = 0; i < encryptedLen; i++) {
        wchar_t hex[3];
        swprintf(hex, 3, L"%02X", buffer[i]);
        result += UnicodeString(hex);
    }

    return result;
}

UnicodeString __fastcall XCryptRSAPwd::DecryptString(UnicodeString str) {
	UnicodeString result;

    // Convertir la chaîne hexadécimale en données binaires
    int strLen = str.Length();
    if (strLen % 2 != 0) return L""; // La chaîne hexadécimale doit avoir une longueur paire

    DWORD dataLen = strLen / 2;
	buffer = new BYTE[dataLen];

    if (!buffer) return L"";

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
	if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer, &decryptedLen)) { return L""; }

    // Convertir les données déchiffrées en UnicodeString
    buffer[decryptedLen] = 0; // Ajouter un terminateur nul
    result = UnicodeString((char*)buffer);

    return result;
}

//---------------------------------------------------------------------------
// Crypte / Decrypte une un fichier - RSA AES par Password (sans clé)
//---------------------------------------------------------------------------
bool __fastcall XCryptRSAPwd::EncryptFile(UnicodeString infile, UnicodeString outfile) {
	bool success = false;

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
			if (!CryptEncrypt(hKey, 0, isFinalBlock, 0, buffer, &encryptedSize, BUFFER_SIZE)) {
				throw std::runtime_error("Erreur lors du chiffrement");
			}

			// Écrire le bloc chiffré
			outFile.write((char*)buffer, encryptedSize);
		}

		success = true;
	}
	catch (const std::exception&) {
		success = false;
	}
	
	Cleanup:
	inFile.close();
	outFile.close();
	
	return success;
}

bool __fastcall XCryptRSAPwd::DecryptFile(UnicodeString infile, UnicodeString outfile) {
	bool success = false;
	
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
			if (!CryptDecrypt(hKey, 0, isFinalBlock, 0, buffer, &decryptedSize)) {
				throw std::runtime_error("Erreur lors du déchiffrement");
			}

			// Écrire le bloc déchiffré
			outFile.write((char*)buffer, decryptedSize);
		}

		success = true;
	}
	catch (const std::exception&) {
		success = false;
	}

	Cleanup:
	inFile.close();
	outFile.close();
	
	return success;
}

