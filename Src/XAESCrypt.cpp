#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XAESCrypt.h"

XAESCrypt::XAESCrypt(void) {
}

XAESCrypt::~XAESCrypt(void) {
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
		std::cerr << "Erreur: " << e.what() << std::endl;
        return false;
    }
}

bool __fastcall XAESCrypt::DecryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key) {
	try {
		std::vector<BYTE> fileBuffer = FileToBuffer(infile);
		std::vector<BYTE> decryptedData = DecryptBuffer(fileBuffer, key);
		return BufferToFile(decryptedData, outfile);
    } catch (const std::exception& e) {
		std::cerr << "Erreur: " << e.what() << std::endl;
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
// Buffer <> Unicode
//---------------------------------------------------------------------------
UnicodeString __fastcall XAESCrypt::BufferToUnicode(const std::vector<BYTE>& buffer) {
	std::string str(reinterpret_cast<const char*>(buffer.data()), buffer.size());
	size_t nullPos = str.find('\0');
	if (nullPos != std::string::npos) str = str.substr(0, nullPos);
	return UnicodeString(str.c_str());
}

std::vector<BYTE> __fastcall XAESCrypt::UnicodeToBuffer(UnicodeString str) {
    std::string data = UnicodeToString(str);
    return std::vector<BYTE>(data.begin(), data.end());
}

//---------------------------------------------------------------------------
// Buffer <> File
//---------------------------------------------------------------------------
bool __fastcall XAESCrypt::BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile) {
	std::string outputFile = UnicodeToString(outfile);
	std::ofstream outFile(outputFile, std::ios::binary);
	if (!outFile) return false;
	outFile.write((char*)buffer.data(), buffer.size());
	return true;
}

std::vector<BYTE> __fastcall XAESCrypt::FileToBuffer(UnicodeString infile) {
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

UnicodeString __fastcall XAESCrypt::BufferToHex(const std::vector<BYTE>& buffer) {
	UnicodeString hexString;
	for (BYTE byte : buffer) {
		wchar_t hex[3];
		swprintf(hex, 3, L"%02X", byte);
		hexString += UnicodeString(hex);
	}
	return hexString;
}

std::vector<BYTE> __fastcall XAESCrypt::HexToBuffer(UnicodeString hexStr) {
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
// Conversion Unicode -> String
//---------------------------------------------------------------------------
std::string __fastcall XAESCrypt::UnicodeToString(const UnicodeString& ustr) {
	AnsiString ansi(ustr);
	return std::string(ansi.c_str());
}

//---------------------------------------------------------------------------
// Retourne une clé AES et la longueur de la clé
//---------------------------------------------------------------------------
BYTE* __fastcall XAESCrypt::RandomAesIVKey(DWORD* keySize) {
//	const DWORD AES_KEY_SIZE = 32;
//	const DWORD AES_IV_SIZE  = 16;
//	const DWORD TOTAL_SIZE   = AES_KEY_SIZE + AES_IV_SIZE;
//
//	// Allouer la mémoire pour la clé et l'IV
//	BYTE* key = new BYTE[TOTAL_SIZE];
//	if (!key) return NULL;
//
//	// Définir la taille de la clé AES (256 bits = 32 octets) et de l'IV (128 bits = 16 octets)
//	// Générer une clé et un IV aléatoires
//	if (!CryptGenRandom(hProv, TOTAL_SIZE, key)) { delete[] key; return NULL; }
//
//	// Définir la taille totale
//	if (keySize) *keySize = TOTAL_SIZE;
//
//	return key;
}



