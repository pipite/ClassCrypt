//---------------------------------------------------------------------------
#include "TestCryptPCH1.h"
#pragma hdrstop

#include "TMain.h"

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TMain *Main;
//---------------------------------------------------------------------------
__fastcall TMain::TMain(TComponent* Owner)
	: TForm(Owner)
{
	GenPassword = new XPassword();
	AESPwd      = new XAESPwd();
	RSAPwd      = new XRSAPwd();
}

void __fastcall TMain::FormClose(TObject *Sender, TCloseAction &Action)
{
	delete GenPassword;
	delete AESPwd;
	delete RSAPwd;
}

//---------------------------------------------------------------------------
//          XPassword
//---------------------------------------------------------------------------

void __fastcall TMain::BtPasswordClick(TObject *Sender)
{
	EdPassword->Text = GenPassword->NewSecurePassword(NumberBox1->Value);
}

void __fastcall TMain::CBVisibleClick(TObject *Sender)
{
	if ( CBVisible->Checked ) {
		EdPassword->PasswordChar = char(0);
	} else {
		EdPassword->PasswordChar = '*';
	}
}

void __fastcall TMain::EdPasswordChange(TObject *Sender)
{
	AESPwd->SetPassword(EdPassword->Text);
}

//---------------------------------------------------------------------------
//          XAESPwd
//---------------------------------------------------------------------------
// String
void __fastcall TMain::WinEncryptClick(TObject *Sender)
{
	EdWinEncrypt->Text = AESPwd->EncryptString(EdExemple->Text);
}

void __fastcall TMain::WinDecryptClick(TObject *Sender)
{
	EdWinEncrypt->Text = AESPwd->DecryptString(EdWinEncrypt->Text);
}

// File
void __fastcall TMain::BtWinCryptFileClick(TObject *Sender)
{
	if ( AESPwd->EncryptFile(EdFilepath->Text, EdFilepath->Text + ".Crypt") ) {
		LabelWinCrypt->Caption = "Fichier Crypté.";
	} else {
		LabelWinCrypt->Caption = "Echec du cryptage";
	}
}

void __fastcall TMain::BtWinDecryptFileClick(TObject *Sender)
{
	if ( AESPwd->DecryptFile(EdFilepath->Text + ".Crypt", EdFilepath->Text + ".Crypt.png") ) {
		LabelWinCrypt->Caption = "Fichier Décrypté.";
	} else {
		LabelWinCrypt->Caption = "Echec du décryptage";
	}
}

//---------------------------------------------------------------------------
//          XRSAKey  Private Public Key
//---------------------------------------------------------------------------
void __fastcall TMain::BtCreateKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->GenerateKeyPair() ) {
		LbRSAKey->Caption = "Paire de clé RSA généré.";
	} else {
		LbRSAKey->Caption = "Erreur à la création de la paire de clé .RSA";
	}
}

void __fastcall TMain::BtLoadPrivateRsaKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ImportKey("private.blob") ) {
		LbRSAKey->Caption = "Clé private.blob chargé.";
	} else {
		LbRSAKey->Caption = "Erreur au chargement de la clé private.blob";
	}
}

void __fastcall TMain::BtLoadPublicRsaKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ImportKey("public.blob") ) {
		LbRSAKey->Caption = "Clé public.blob chargé.";
	} else {
		LbRSAKey->Caption = "Erreur au chargement de la clé publique.blob";
	}
}

void __fastcall TMain::BtExportRSAPrivateKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ExportPrivateKey("private.blob") ) {
		LbRSAKey->Caption = "Clé privé sauvegardé.";
	} else {
		LbRSAKey->Caption = "Erreur à la sauvegarde de la clé privé";
	}
}

void __fastcall TMain::BtExportRSAPublicKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ExportPublicKey("public.blob") ) {
		LbRSAKey->Caption = "Clé public.blob sauvegardé.";
	} else {
		LbRSAKey->Caption = "Erreur à la sauvegarde de la clé public.blob";
	}
}

//---------------------------------------------------------------------------
//          XCryptRSAKey
//---------------------------------------------------------------------------

void __fastcall TMain::BtEncryptKeyStringClick(TObject *Sender)
{
//	EdWinEncrypt->Text = RSAKey->EncryptString(EdExemple->Text);
}

void __fastcall TMain::Button5Click(TObject *Sender)
{
//	EdWinEncrypt->Text = RSAKey->DecryptString(EdWinEncrypt->Text);
}

void __fastcall TMain::Button6Click(TObject *Sender)
{//	if ( RSAKey->EncryptFile(EdFilepath->Text, EdFilepath->Text + ".Crypt") ) {
//		Label6->Caption = "Fichier Crypté.";
//	} else {
//		Label6->Caption = "Echec du cryptage";
//	}
}

void __fastcall TMain::Button3Click(TObject *Sender)
{
//	if ( RSAKey->DecryptFile(EdFilepath->Text + ".Crypt", EdFilepath->Text + ".Crypt.png") ) {
//		Label6->Caption = "Fichier Décrypté.";
//	} else {
//		Label6->Caption = "Echec du décryptage";
//	}
}

//---------------------------------------------------------------------------
//          Run as User
//---------------------------------------------------------------------------
void __fastcall TMain::Button1Click(TObject *Sender)
{
	// Informations d'identification
	String username = Edit2->Text;
	String domain   = Edit3->Text;  // Domaine ou machine locale (par exemple, ".")
	String password = EdPassword->Text;

	// Programme à lancer
	String programToRun = Edit1->Text ; // Exemple : Notepad

    // Structure pour démarrer le processus
    STARTUPINFO si;
	PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Conversion des chaînes String en tableaux de caractères Unicode (LPCWSTR)
    wchar_t* wUsername = username.c_str();
    wchar_t* wDomain = domain.c_str();
    wchar_t* wPassword = password.c_str();
	wchar_t* wProgramToRun = programToRun.c_str();

    // Utilisation de CreateProcessWithLogonW pour démarrer le processus avec les informations d'identification fournies
    BOOL result = CreateProcessWithLogonW(
        wUsername,            // Nom d'utilisateur
        wDomain,              // Domaine ou machine locale
        wPassword,            // Mot de passe
        LOGON_WITH_PROFILE,    // Crée un profil pour l'utilisateur
        NULL,                 // Application à exécuter (NULL si spécifiée dans wProgramToRun)
        wProgramToRun,        // Ligne de commande de l'application
        CREATE_DEFAULT_ERROR_MODE, // Options de création
        NULL,                 // Variables d'environnement (NULL pour utiliser celles par défaut)
        NULL,                 // Répertoire de travail (NULL pour le répertoire par défaut)
        &si,                  // Informations de démarrage
        &pi                   // Informations sur le processus créé
    );

    if (result)
    {
        // Si le processus a été démarré correctement, afficher un message de succès
		WaitForSingleObject(pi.hProcess, INFINITE);
        ShowMessage("Programme démarré avec succès sous l'autre compte utilisateur.");
		// Attendre que le processus se termine

        // Nettoyage des handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        // En cas d'échec, afficher un message d'erreur
        DWORD errorCode = GetLastError();
		ShowMessage("Échec du lancement du programme.");
	}
}

void __fastcall TMain::Button4Click(TObject *Sender)
{
//	RSA_AES->Show();
}
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------

