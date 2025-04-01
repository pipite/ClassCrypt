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
	RSAKey      = new XRSAKey();
}

void __fastcall TMain::FormClose(TObject *Sender, TCloseAction &Action)
{
	delete GenPassword;
	delete AESPwd;
	delete RSAPwd;
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
	// Securise le Password avec un hachage SHA-256
	AESPwd->SetSecurePassword(EdPassword->Text);
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
	if ( RSAKey->GenerateKeyPair() ) {
		LbRSAKey->Caption = "Paire de cl� RSA g�n�r�.";
	} else {
		LbRSAKey->Caption = "Erreur � la cr�ation de la paire de cl� .RSA";
	}
}

void __fastcall TMain::BtLoadPrivateRsaKeyClick(TObject *Sender)
{
	if ( RSAKey->ImportKey("private.blob") ) {
		LbRSAKey->Caption = "Cl� private.blob charg�.";
	} else {
		LbRSAKey->Caption = "Erreur au chargement de la cl� private.blob";
	}
}

void __fastcall TMain::BtLoadPublicRsaKeyClick(TObject *Sender)
{
	if ( RSAKey->ImportKey("public.blob") ) {
		LbRSAKey->Caption = "Cl� public.blob charg�.";
	} else {
		LbRSAKey->Caption = "Erreur au chargement de la cl� publique.blob";
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

//---------------------------------------------------------------------------
//          XCryptRSAKey
//---------------------------------------------------------------------------

void __fastcall TMain::BtRSAPublicKeyEncryptClick(TObject *Sender)
{
	if ( RSAKey->ImportKey("public.blob") ) {
		EdRSACrypt->Text = RSAKey->EncryptString(EdRSAExemple->Text);
	}
}

void __fastcall TMain::BtRSAPrivateKeyDecryptClick(TObject *Sender)
{
	if ( RSAKey->ImportKey("private.blob") ) {
		EdRSACrypt->Text = RSAKey->DecryptString(EdRSACrypt->Text);
	}
}

void __fastcall TMain::BtRSAPublicKeyCryptFileClick(TObject *Sender)
{
	if ( RSAKey->ImportKey("public.blob") ) {
		if ( RSAKey->EncryptFile(EdRSAFile->Text, EdRSAFile->Text + ".Crypt") ) {
			LbRSACrypt->Caption = "Fichier Crypt�.";
		} else {
			LbRSACrypt->Caption = "Echec du cryptage";
		}
	}
}
void __fastcall TMain::BtRSAPrivateKeyDeCryptFileClick(TObject *Sender)
{
	if ( RSAKey->ImportKey("private.blob") ) {
		if ( RSAKey->DecryptFile(EdRSAFile->Text + ".Crypt", EdRSAFile->Text + ".Crypt.png") ) {
			LbRSACrypt->Caption = "Fichier D�crypt�.";
		} else {
			LbRSACrypt->Caption = "Echec du d�cryptage";
		}
	}
}


//---------------------------------------------------------------------------
//          Run as User
//---------------------------------------------------------------------------
void __fastcall TMain::Button1Click(TObject *Sender)
{
	GenPassword->RunAsUser(Edit2->Text, Edit3->Text, EdPassword->Text, Edit1->Text);
}

void __fastcall TMain::Button4Click(TObject *Sender)
{
//	RSA_AES->Show();
}


