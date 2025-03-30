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
	SimpleCrypt = new XSimpleCrypt();
	GenPassword = new XPassword();
	CryptRSAPwd = new XCryptRSAPwd();
	RSAKey      = new XRSAKey();
}

void __fastcall TMain::FormClose(TObject *Sender, TCloseAction &Action)
{
	delete SimpleCrypt;
	delete CryptRSAPwd;
	delete GenPassword;
	delete RSAKey;
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
	EdEncode->Text = SimpleCrypt->Encode(EdPassword->Text);
	EdEncrypt->Text = SimpleCrypt->Encrypt(EdPassword->Text);
	CryptRSAPwd->SetPassword(EdPassword->Text);
}

//---------------------------------------------------------------------------
//          XSimpleCrypt
//---------------------------------------------------------------------------
void __fastcall TMain::BtEncodeClick(TObject *Sender)
{
	EdEncode->Text = SimpleCrypt->Encode(EdPassword->Text);
}

void __fastcall TMain::BtDecodeClick(TObject *Sender)
{
	EdEncode->Text = SimpleCrypt->Encode(EdPassword->Text);
	EdEncode->Text = SimpleCrypt->Encode(EdEncode->Text);
}

void __fastcall TMain::BtEncryptClick(TObject *Sender)
{
	EdEncrypt->Text = SimpleCrypt->Encrypt(EdPassword->Text);
}

void __fastcall TMain::BtDecryptClick(TObject *Sender)
{
	EdEncrypt->Text = SimpleCrypt->Encrypt(EdPassword->Text);
	EdEncrypt->Text = SimpleCrypt->Decrypt(EdEncrypt->Text);
}

//---------------------------------------------------------------------------
//          XCryptRSAPwd
//---------------------------------------------------------------------------
// String
void __fastcall TMain::WinEncryptClick(TObject *Sender)
{
	EdWinEncrypt->Text = CryptRSAPwd->EncryptString(EdExemple->Text);
}

void __fastcall TMain::WinDecryptClick(TObject *Sender)
{
	EdWinEncrypt->Text = CryptRSAPwd->DecryptString(EdWinEncrypt->Text);
}

// File
void __fastcall TMain::BtWinCryptFileClick(TObject *Sender)
{
	if ( CryptRSAPwd->EncryptFile(EdFilepath->Text, EdFilepath->Text + ".Crypt") ) {
		LabelWinCrypt->Caption = "Fichier Crypt�.";
	} else {
		LabelWinCrypt->Caption = "Echec du cryptage";
	}
}

void __fastcall TMain::BtWinDecryptFileClick(TObject *Sender)
{
	if ( CryptRSAPwd->DecryptFile(EdFilepath->Text + ".Crypt", EdFilepath->Text + ".Crypt.png") ) {
		LabelWinCrypt->Caption = "Fichier D�crypt�.";
	} else {
		LabelWinCrypt->Caption = "Echec du d�cryptage";
	}
}

//---------------------------------------------------------------------------
//          WinEncrypt Private / Public Key
//---------------------------------------------------------------------------
void __fastcall TMain::BtCreateKeyClick(TObject *Sender)
{
	if ( RSAKey->GenerateKeyPair() ) {
		LbRSAKey->Caption = "Paire de cl� RSA g�n�r�.";
	} else {
		LbRSAKey->Caption = "Erreur � la cr�ation de la paire de cl� .RSA";
	}
}

void __fastcall TMain::BtExportRSAPrivateKeyClick(TObject *Sender)
{
	if ( RSAKey->ExportPrivateKey("private.blob") ) {
		LbRSAKey->Caption = "Cl� priv� sauvegard�.";
	} else {
		LbRSAKey->Caption = "Erreur � la sauvegarde de la cl� priv�";
	}
}

void __fastcall TMain::BtExportRSAPublicKeyClick(TObject *Sender)
{
	if ( RSAKey->ExportPublicKey("public.blob") ) {
		LbRSAKey->Caption = "Cl� public.blob sauvegard�.";
	} else {
		LbRSAKey->Caption = "Erreur � la sauvegarde de la cl� public.blob";
	}
}

void __fastcall TMain::BtLoadRsaKeyClick(TObject *Sender)
{
	if ( RSAKey->ImportKey("private.blob") ) {
		LbRSAKey->Caption = "Cl� private.blob charg�.";
	} else {
		LbRSAKey->Caption = "Erreur au chargement de la cl� private.blob";
	}
}

//---------------------------------------------------------------------------
//          WinEncrypt Magasin de cl�
//---------------------------------------------------------------------------



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


//---------------------------------------------------------------------------


//---------------------------------------------------------------------------

