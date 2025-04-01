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
		LabelWinCrypt->Caption = "Fichier Crypt�.";
	} else {
		LabelWinCrypt->Caption = "Echec du cryptage";
	}
}

void __fastcall TMain::BtWinDecryptFileClick(TObject *Sender)
{
	if ( AESPwd->DecryptFile(EdFilepath->Text + ".Crypt", EdFilepath->Text + ".Crypt.png") ) {
		LabelWinCrypt->Caption = "Fichier D�crypt�.";
	} else {
		LabelWinCrypt->Caption = "Echec du d�cryptage";
	}
}

//---------------------------------------------------------------------------
//          XRSAKey  Private Public Key
//---------------------------------------------------------------------------
void __fastcall TMain::BtCreateKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->GenerateKeyPair() ) {
		LbRSAKey->Caption = "Paire de cl� RSA g�n�r�.";
	} else {
		LbRSAKey->Caption = "Erreur � la cr�ation de la paire de cl� .RSA";
	}
}

void __fastcall TMain::BtLoadPrivateRsaKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ImportKey("private.blob") ) {
		LbRSAKey->Caption = "Cl� private.blob charg�.";
	} else {
		LbRSAKey->Caption = "Erreur au chargement de la cl� private.blob";
	}
}

void __fastcall TMain::BtLoadPublicRsaKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ImportKey("public.blob") ) {
		LbRSAKey->Caption = "Cl� public.blob charg�.";
	} else {
		LbRSAKey->Caption = "Erreur au chargement de la cl� publique.blob";
	}
}

void __fastcall TMain::BtExportRSAPrivateKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ExportPrivateKey("private.blob") ) {
		LbRSAKey->Caption = "Cl� priv� sauvegard�.";
	} else {
		LbRSAKey->Caption = "Erreur � la sauvegarde de la cl� priv�";
	}
}

void __fastcall TMain::BtExportRSAPublicKeyClick(TObject *Sender)
{
	if ( RSAPwd->RSAKey->ExportPublicKey("public.blob") ) {
		LbRSAKey->Caption = "Cl� public.blob sauvegard�.";
	} else {
		LbRSAKey->Caption = "Erreur � la sauvegarde de la cl� public.blob";
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
//		Label6->Caption = "Fichier Crypt�.";
//	} else {
//		Label6->Caption = "Echec du cryptage";
//	}
}

void __fastcall TMain::Button3Click(TObject *Sender)
{
//	if ( RSAKey->DecryptFile(EdFilepath->Text + ".Crypt", EdFilepath->Text + ".Crypt.png") ) {
//		Label6->Caption = "Fichier D�crypt�.";
//	} else {
//		Label6->Caption = "Echec du d�cryptage";
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

	// Programme � lancer
	String programToRun = Edit1->Text ; // Exemple : Notepad

    // Structure pour d�marrer le processus
    STARTUPINFO si;
	PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Conversion des cha�nes String en tableaux de caract�res Unicode (LPCWSTR)
    wchar_t* wUsername = username.c_str();
    wchar_t* wDomain = domain.c_str();
    wchar_t* wPassword = password.c_str();
	wchar_t* wProgramToRun = programToRun.c_str();

    // Utilisation de CreateProcessWithLogonW pour d�marrer le processus avec les informations d'identification fournies
    BOOL result = CreateProcessWithLogonW(
        wUsername,            // Nom d'utilisateur
        wDomain,              // Domaine ou machine locale
        wPassword,            // Mot de passe
        LOGON_WITH_PROFILE,    // Cr�e un profil pour l'utilisateur
        NULL,                 // Application � ex�cuter (NULL si sp�cifi�e dans wProgramToRun)
        wProgramToRun,        // Ligne de commande de l'application
        CREATE_DEFAULT_ERROR_MODE, // Options de cr�ation
        NULL,                 // Variables d'environnement (NULL pour utiliser celles par d�faut)
        NULL,                 // R�pertoire de travail (NULL pour le r�pertoire par d�faut)
        &si,                  // Informations de d�marrage
        &pi                   // Informations sur le processus cr��
    );

    if (result)
    {
        // Si le processus a �t� d�marr� correctement, afficher un message de succ�s
		WaitForSingleObject(pi.hProcess, INFINITE);
        ShowMessage("Programme d�marr� avec succ�s sous l'autre compte utilisateur.");
		// Attendre que le processus se termine

        // Nettoyage des handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        // En cas d'�chec, afficher un message d'erreur
        DWORD errorCode = GetLastError();
		ShowMessage("�chec du lancement du programme.");
	}
}

void __fastcall TMain::Button4Click(TObject *Sender)
{
//	RSA_AES->Show();
}
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------

