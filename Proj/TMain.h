#ifndef TMainH
#define TMainH
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.Mask.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.NumberBox.hpp>

#include "XPassword.h"
#include "XAESPwd.h"
#include "XRSAPwd.h"

//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
class TMain : public TForm
{
__published:	// Composants gérés par l'EDI
	TEdit *Edit1;
	TButton *Button1;
	TEdit *Edit2;
	TEdit *Edit3;
	TLabel *Label1;
	TLabel *Label2;
	TMaskEdit *EdPassword;
	TLabel *Label4;
	TCheckBox *CBVisible;
	TButton *BtPassword;
	TNumberBox *NumberBox1;
	TLabel *LabelWinCrypt;
	TButton *BtWinCryptFile;
	TButton *BtWinDecryptFile;
	TEdit *EdExemple;
	TButton *WinEncrypt;
	TEdit *EdWinEncrypt;
	TButton *WinDecrypt;
	TEdit *EdFilepath;
	TButton *BtCreateKey;
	TButton *BtLoadPublicRsaKey;
	TButton *BtExportRSAPrivateKey;
	TButton *BtExportRSAPublicKey;
	TLabel *LbRSAKey;
	TLabel *Label3;
	TLabel *Label5;
	TLabel *Label6;
	TButton *Button2;
	TButton *Button3;
	TButton *Button4;
	TButton *Button5;
	TButton *BtLoadPrivateRsaKey;
	void __fastcall Button1Click(TObject *Sender);
	void __fastcall BtWinCryptFileClick(TObject *Sender);
	void __fastcall FormClose(TObject *Sender, TCloseAction &Action);
	void __fastcall CBVisibleClick(TObject *Sender);
	void __fastcall BtPasswordClick(TObject *Sender);
	void __fastcall EdPasswordChange(TObject *Sender);
	void __fastcall BtWinDecryptFileClick(TObject *Sender);
	void __fastcall WinEncryptClick(TObject *Sender);
	void __fastcall WinDecryptClick(TObject *Sender);
	void __fastcall BtCreateKeyClick(TObject *Sender);
	void __fastcall BtExportRSAPrivateKeyClick(TObject *Sender);
	void __fastcall BtExportRSAPublicKeyClick(TObject *Sender);
	void __fastcall BtLoadPublicRsaKeyClick(TObject *Sender);
	void __fastcall BtEncryptKeyStringClick(TObject *Sender);
	void __fastcall Button5Click(TObject *Sender);
	void __fastcall BtLoadPrivateRsaKeyClick(TObject *Sender);
	void __fastcall Button3Click(TObject *Sender);
	void __fastcall Button4Click(TObject *Sender);
	void __fastcall Button6Click(TObject *Sender);
private:	// Déclarations utilisateur
	XPassword    *GenPassword;
	XAESCrypt    *AESCrypt;
	XAESPwd      *AESPwd;
	XRSAPwd      *RSAPwd;

public:		// Déclarations utilisateur
	__fastcall TMain(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TMain *Main;
//---------------------------------------------------------------------------
#endif
