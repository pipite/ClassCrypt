#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XBuffTool.h"

XBuffTool::XBuffTool(void) {
}

XBuffTool::~XBuffTool(void) {
}

std::vector<BYTE> __fastcall XBuffTool::DecryptBuffer(const std::vector<BYTE>& encryptedData, HCRYPTKEY key) {
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
UnicodeString __fastcall XBuffTool::BufferToUnicode(const std::vector<BYTE>& buffer) {
	std::string str(reinterpret_cast<const char*>(buffer.data()), buffer.size());
	size_t nullPos = str.find('\0');
	if (nullPos != std::string::npos) str = str.substr(0, nullPos);
	return UnicodeString(str.c_str());
}

std::vector<BYTE> __fastcall XBuffTool::UnicodeToBuffer(UnicodeString str) {
    std::string data = UnicodeToString(str);
    return std::vector<BYTE>(data.begin(), data.end());
}

//---------------------------------------------------------------------------
// Buffer <> File
//---------------------------------------------------------------------------
bool __fastcall XBuffTool::BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile) {
	std::string outputFile = UnicodeToString(outfile);
	std::ofstream outFile(outputFile, std::ios::binary);
	if (!outFile) return false;
	outFile.write((char*)buffer.data(), buffer.size());
	return true;
}

std::vector<BYTE> __fastcall XBuffTool::FileToBuffer(UnicodeString infile) {
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

UnicodeString __fastcall XBuffTool::BufferToHex(const std::vector<BYTE>& buffer) {
	UnicodeString hexString;
	for (BYTE byte : buffer) {
		wchar_t hex[3];
		swprintf(hex, 3, L"%02X", byte);
		hexString += UnicodeString(hex);
	}
	return hexString;
}

std::vector<BYTE> __fastcall XBuffTool::HexToBuffer(UnicodeString hexStr) {
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
std::string __fastcall XBuffTool::UnicodeToString(const UnicodeString& ustr) {
	AnsiString ansi(ustr);
	return std::string(ansi.c_str());
}



