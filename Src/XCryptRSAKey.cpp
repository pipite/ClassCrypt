#include "TestCryptPCH1.h"
#pragma hdrstop

#include "XCryptRSAKey.h"

XCryptRSAKey::XCryptRSAKey(void) {
	hProv        = NULL;
	hKey         = NULL;
}

XCryptRSAKey::~XCryptRSAKey(void) {
	ClearKey();
}

UnicodeString XCrypt::BytesToHexString(const std::vector<BYTE>& data) {
	std::wstringstream hexStream;
	for (BYTE b : data) {
		hexStream << std::setw(2) << std::setfill(L'0') << std::hex << (int)b;
	}
	return hexStream.str().c_str();
}


// A terminer ...


UnicodeString __fastcall XCrypt::EncryptStringWithPublicKey(const UnicodeString& input) {
   std::vector<BYTE> encryptedData;

//	// 1️⃣ Ouvrir ou obtenir un conteneur de clés contenant la clé publique
//	if (!CryptAcquireContext(&hProv, "MyKeyContainer", NULL, PROV_RSA_FULL, 0)) {
//		return L"";
//	}
//
//	// 2️⃣ Récupérer la clé publique du conteneur
//	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
//		CryptReleaseContext(hProv, 0);
//		return L"";
//	}

//	// 3️⃣ Convertir la chaîne d'entrée en un tableau de bytes
//	DWORD dataLen = input.Length() * sizeof(WCHAR);
//	encryptedData.resize(dataLen);
//	memcpy(encryptedData.data(), input.c_str(), dataLen);
//
//	// 4️⃣ Chiffrer les données avec la clé publique
//	DWORD bufLen = dataLen;
//	if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData.data(), &dataLen, encryptedData.size())) {
//		CryptDestroyKey(hKey);
//		CryptReleaseContext(hProv, 0);
//		return L"";
//	}
//
//	// 5️⃣ Libération des ressources
//	CryptDestroyKey(hKey);
//	CryptReleaseContext(hProv, 0);
//
//	// 6️⃣ Convertir les données chiffrées en une chaîne hexadécimale
//	UnicodeString hexEncryptedData = BytesToHexString(encryptedData);

//	return hexEncryptedData;
}

bool ExtractPublicKeyFromPrivateKey(void) {
//	DWORD dwDataLen;
//	BYTE* pbPublicKeyBlob = NULL;
//
//	// Exporter la clé privée pour obtenir la clé publique
//	if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwDataLen)) {
//		std::cerr << "Erreur CryptExportKey (taille blob publique): " << GetLastError() << std::endl;
//		return false;
//	}
//
//	pbPublicKeyBlob = new BYTE[dwDataLen];
//	if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, pbPublicKeyBlob, &dwDataLen)) {
//		std::cerr << "Erreur CryptExportKey (exportation de la clé publique): " << GetLastError() << std::endl;
//		delete[] pbPublicKeyBlob;
//		return false;
//	}
//
//	// Importer la clé publique à partir du blob
//	if (!CryptImportKey(hProv, pbPublicKeyBlob, dwDataLen, 0, 0, &hPublicKey)) {
//		std::cerr << "Erreur CryptImportKey: " << GetLastError() << std::endl;
//		delete[] pbPublicKeyBlob;
//		return false;
//	}
//
//    delete[] pbPublicKeyBlob;
    return true;
}

//---------------------------------------------------------------------------
// Gestion des magasins de clés
//---------------------------------------------------------------------------

