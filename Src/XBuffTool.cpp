#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XBuffTool.h"

//---------------------------------------------------------------------------
// Buffer <> Unicode
//---------------------------------------------------------------------------
UnicodeString __fastcall BufferToUnicode(const std::vector<BYTE>& buffer) {
	std::string str(reinterpret_cast<const char*>(buffer.data()), buffer.size());
	size_t nullPos = str.find('\0');
	if (nullPos != std::string::npos) str = str.substr(0, nullPos);
	return UnicodeString(str.c_str());
}

std::vector<BYTE> __fastcall UnicodeToBuffer(UnicodeString str) {
    std::string data = UnicodeToString(str);
    return std::vector<BYTE>(data.begin(), data.end());
}

//---------------------------------------------------------------------------
// Buffer <> File
//---------------------------------------------------------------------------
bool __fastcall BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile) {
	std::string outputFile = UnicodeToString(outfile);
	std::ofstream outFile(outputFile, std::ios::binary);
	if (!outFile) return false;
	outFile.write((char*)buffer.data(), buffer.size());
	return true;
}

std::vector<BYTE> __fastcall FileToBuffer(UnicodeString infile) {
	std::string inputFile = UnicodeToString(infile);
	std::ifstream inFile(inputFile, std::ios::binary);

	if (!inFile) throw std::runtime_error("Impossible d'ouvrir le fichier d'entrée");

	inFile.seekg(0, std::ios::end);
	std::streamsize fileSize = inFile.tellg();
	inFile.seekg(0, std::ios::beg);

	if (fileSize == 0) return {};

	std::vector<BYTE> buffer(fileSize);
	inFile.read(reinterpret_cast<char*>(buffer.data()), fileSize);

	return buffer;
}

//---------------------------------------------------------------------------
// Buffer <> Hexa Unicode
//---------------------------------------------------------------------------

UnicodeString __fastcall BufferToHex(const std::vector<BYTE>& buffer) {
	UnicodeString hexString;
	for (BYTE byte : buffer) {
		wchar_t hex[3];
		swprintf(hex, 3, L"%02X", byte);
		hexString += UnicodeString(hex);
	}
	return hexString;
}

std::vector<BYTE> __fastcall HexToBuffer(UnicodeString hexStr) {
	std::vector<BYTE> buffer;
	int len = hexStr.Length();

	if (len % 2 != 0) throw std::runtime_error("Erreur: Chaîne hexadécimale invalide");
    for (int i = 1; i <= len; i += 2) {
		wchar_t hexByte[3] = { hexStr[i], hexStr[i+1], 0 };
        int value;
        swscanf(hexByte, L"%x", &value);
		buffer.push_back((BYTE)value);
	}
    return buffer;
}

//---------------------------------------------------------------------------
// Extract / Add AES key to Data
//---------------------------------------------------------------------------
// Extrait la clé AES chiffrée du buffer et modifie le buffer pour qu'il ne contienne plus que les données
std::vector<BYTE> __fastcall ExtractAESKey(std::vector<BYTE> &buffer) {
	// Vérifier que le buffer est assez grand pour contenir au moins la taille de la clé
    if (buffer.size() < sizeof(DWORD)) {
        throw std::runtime_error("Format de buffer invalide ou buffer corrompu");
    }

    // Extraire la taille de la clé AES chiffrée
    DWORD encryptedKeySize = 0;
    memcpy(&encryptedKeySize, buffer.data(), sizeof(DWORD));

    // Vérifier que la taille de la clé est valide
    if (encryptedKeySize == 0 || encryptedKeySize > 1024 ||
        buffer.size() < sizeof(DWORD) + encryptedKeySize) {
        throw std::runtime_error("Format de buffer invalide ou clé AES corrompue");
    }

    // Extraire la clé AES chiffrée
    std::vector<BYTE> encryptedKeyBlob(encryptedKeySize);
    memcpy(encryptedKeyBlob.data(), buffer.data() + sizeof(DWORD), encryptedKeySize);

    // Calculer la taille du header (taille de la clé + clé)
    size_t headerSize = sizeof(DWORD) + encryptedKeySize;

    // Modifier le buffer pour qu'il ne contienne plus que les données
    // On déplace les données vers le début du buffer
    size_t dataSize = buffer.size() - headerSize;
    if (dataSize > 0) {
        memmove(buffer.data(), buffer.data() + headerSize, dataSize);
    }

    // Redimensionner le buffer pour qu'il ne contienne plus que les données
    buffer.resize(dataSize);

    return encryptedKeyBlob;
}

// Ajoute une clé AES (sous forme de buffer) aux données en modifiant directement le buffer data
bool __fastcall AddAESKeyToData(std::vector<BYTE> &data, const std::vector<BYTE> &keyBuffer) {
	try {
        // Vérifier que le buffer de clé n'est pas vide
        if (keyBuffer.empty()) {
            throw std::runtime_error("Buffer de clé AES vide");
        }

        // Sauvegarder la taille originale des données
        size_t originalDataSize = data.size();

        // Calculer la nouvelle taille du buffer
        size_t newSize = sizeof(DWORD) + keyBuffer.size() + originalDataSize;

        // Redimensionner le buffer de données pour accueillir l'en-tête et la clé
        data.resize(newSize);

        // Déplacer les données originales vers la fin du buffer
        // Commencer par la fin pour éviter d'écraser des données
        for (size_t i = 0; i < originalDataSize; ++i) {
            size_t srcIdx = originalDataSize - 1 - i;
            size_t destIdx = newSize - 1 - i;
            data[destIdx] = data[srcIdx];
        }

        // Ajouter la taille du buffer de clé au début
        DWORD keySize = keyBuffer.size();
        memcpy(data.data(), &keySize, sizeof(DWORD));

        // Ajouter le buffer de clé après la taille
        memcpy(data.data() + sizeof(DWORD), keyBuffer.data(), keyBuffer.size());

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Erreur lors de l'ajout de la clé AES aux données: " << e.what() << std::endl;
        return false;
    }
}

//---------------------------------------------------------------------------
// Conversion Unicode -> String
//---------------------------------------------------------------------------
std::string __fastcall UnicodeToString(const UnicodeString& ustr) {
	AnsiString ansi(ustr);
	return std::string(ansi.c_str());
}



