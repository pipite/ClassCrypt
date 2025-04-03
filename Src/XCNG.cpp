#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <iostream>
#include <string>

#pragma comment(lib, "bcrypt.lib")

// Générer une clé AES-256 aléatoire
bool GenerateRandomAESKey(std::vector<BYTE>& key) {
    key.resize(32); // Clé AES-256 = 32 octets
    return BCryptGenRandom(NULL, key.data(), key.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
}

// Dériver une clé AES-256 depuis un mot de passe avec PBKDF2
bool GenerateAESKeyFromPassword(const std::string& password, std::vector<BYTE>& salt, std::vector<BYTE>& key) {
    key.resize(32); // Clé AES-256
    salt.resize(16); // Sel de 128 bits
    BCryptGenRandom(NULL, salt.data(), salt.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG); // Générer un sel aléatoire

    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_PBKDF2_ALGORITHM, NULL, 0) != STATUS_SUCCESS) return false;

    if (BCryptDeriveKeyPBKDF2(hAlg, (PBYTE)password.data(), password.size(), salt.data(), salt.size(), 100000, key.data(), key.size(), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

bool EncryptAES_GCM(const std::vector<BYTE>& key, const std::vector<BYTE>& plaintext,
                    std::vector<BYTE>& ciphertext, std::vector<BYTE>& iv, std::vector<BYTE>& tag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    // Ouvrir AES-GCM
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS) return false;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), key.size(), 0) != STATUS_SUCCESS) return false;

    // Générer un IV aléatoire (12 octets recommandé)
    iv.resize(12);
    BCryptGenRandom(NULL, iv.data(), iv.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Configurer AES-GCM
    tag.resize(16);
    ciphertext.resize(plaintext.size());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv.data();
    authInfo.cbNonce = iv.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = tag.size();

    DWORD cbResult = 0;
    if (BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), plaintext.size(), &authInfo, iv.data(), iv.size(),
                      ciphertext.data(), ciphertext.size(), &cbResult, 0) != STATUS_SUCCESS) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

bool DecryptAES_GCM(const std::vector<BYTE>& key, const std::vector<BYTE>& ciphertext,
                    const std::vector<BYTE>& iv, const std::vector<BYTE>& tag, std::vector<BYTE>& plaintext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS) return false;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), key.size(), 0) != STATUS_SUCCESS) return false;

    plaintext.resize(ciphertext.size());

    // Configurer AES-GCM
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.data();
    authInfo.cbNonce = iv.size();
    authInfo.pbTag = (PUCHAR)tag.data();
    authInfo.cbTag = tag.size();

    DWORD cbResult = 0;
    if (BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), ciphertext.size(), &authInfo, (PUCHAR)iv.data(), iv.size(),
                      plaintext.data(), plaintext.size(), &cbResult, 0) != STATUS_SUCCESS) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

int main() {
    std::vector<BYTE> key, salt, iv, tag, ciphertext, decryptedText;
    std::string password = "SuperSecret123";

    // 1. Générer une clé AES-256
    GenerateAESKeyFromPassword(password, salt, key);

    // 2. Définir le message à chiffrer
    std::vector<BYTE> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'C', '+', '+', '!', ' ', 'A', 'E', 'S', '-'};

    // 3. Chiffrement AES-GCM
    if (EncryptAES_GCM(key, plaintext, ciphertext, iv, tag)) {
        std::cout << "Chiffrement réussi !" << std::endl;
    } else {
        std::cerr << "Erreur lors du chiffrement !" << std::endl;
        return -1;
    }

    // 4. Déchiffrement AES-GCM
    if (DecryptAES_GCM(key, ciphertext, iv, tag, decryptedText)) {
        std::cout << "Déchiffrement réussi : ";
        for (auto c : decryptedText) std::cout << (char)c;
        std::cout << std::endl;
    } else {
        std::cerr << "Échec du déchiffrement !" << std::endl;
        return -1;
    }

    return 0;
}

✅ Utilisation de std::vector<BYTE> pour éviter les dépassements mémoire.
✅ Facilité d’extension et gestion automatique des tailles de buffers.

🔹 1️⃣ Génération d'une clé AES-256 sécurisée
On utilise BCryptGenRandom pour une clé aléatoire ou PBKDF2 pour une clé basée sur un mot de passe.


Pourquoi cette solution est optimale ?
🔒 Fonction	🔐 Sécurité
AES-256	Sécurisé contre le brute-force.
AES-GCM	Intègre un tag d’authentification pour éviter la falsification.
PBKDF2 (100 000 itérations)	Protège contre le brute-force et les rainbow tables.
std::vector	Gestion automatique de la mémoire.

🔹 Pourquoi cette implémentation est sécurisée ?
✔ Si le tag est incorrect, le déchiffrement échoue.
✔ Empêche les attaques par modification des données.

🔹 Pourquoi AES-GCM ?
✔ IV unique à chaque chiffrement.
✔ Tag d'authentification pour éviter la falsification.

🔹 Pourquoi utiliser std::vector ?
✔ Gestion automatique de la mémoire (évite les fuites).
✔ Sécurisé contre les dépassements mémoire.
✔ Facile à passer en paramètre.