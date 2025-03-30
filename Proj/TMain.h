#ifndef TMainH
#define TMainH
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.Mask.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.NumberBox.hpp>

#include "XSimpleCrypt.h"
//#include "XCrypt.h"
#include "XPassword.h"
#include "XCryptRSAPwd.h"
#include "XRSAKey.h"


//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
class TMain : public TForm
{
__published:	// Composants gérés par l'EDI
	TEdit *Edit1;
	TButton *Button1;
	TEdit *Edit2;
	TEdit *Edit3;
	TEdit *EdEncode;
	TLabel *Label1;
	TLabel *Label2;
	TMaskEdit *EdPassword;
	TLabel *Label4;
	TCheckBox *CBVisible;
	TButton *BtEncrypt;
	TEdit *EdEncrypt;
	TButton *BtDecrypt;
	TButton *BtDecode;
	TButton *BtPassword;
	TNumberBox *NumberBox1;
	TLabel *LabelWinCrypt;
	TButton *BtWinCryptFile;
	TButton *BtWinDecryptFile;
	TEdit *EdExemple;
	TButton *BtEncode;
	TButton *WinEncrypt;
	TEdit *EdWinEncrypt;
	TButton *WinDecrypt;
	TEdit *EdFilepath;
	TButton *BtCreateKey;
	TButton *BtLoadRsaKey;
	TButton *BtExportRSAPrivateKey;
	TButton *BtExportRSAPublicKey;
	TLabel *LbRSAKey;
	void __fastcall Button1Click(TObject *Sender);
	void __fastcall BtWinCryptFileClick(TObject *Sender);
	void __fastcall FormClose(TObject *Sender, TCloseAction &Action);
	void __fastcall CBVisibleClick(TObject *Sender);
	void __fastcall BtEncryptClick(TObject *Sender);
	void __fastcall BtDecryptClick(TObject *Sender);
	void __fastcall BtDecodeClick(TObject *Sender);
	void __fastcall BtPasswordClick(TObject *Sender);
	void __fastcall EdPasswordChange(TObject *Sender);
	void __fastcall BtWinDecryptFileClick(TObject *Sender);
	void __fastcall BtEncodeClick(TObject *Sender);
	void __fastcall WinEncryptClick(TObject *Sender);
	void __fastcall WinDecryptClick(TObject *Sender);
	void __fastcall BtCreateKeyClick(TObject *Sender);
	void __fastcall BtExportRSAPrivateKeyClick(TObject *Sender);
	void __fastcall BtExportRSAPublicKeyClick(TObject *Sender);
	void __fastcall BtLoadRsaKeyClick(TObject *Sender);
private:	// Déclarations utilisateur
	XSimpleCrypt *SimpleCrypt;
	XPassword    *GenPassword;
//	XCrypt       *Crypt;
	XCryptRSAPwd *CryptRSAPwd;
	XRSAKey      *RSAKey;

public:		// Déclarations utilisateur
	__fastcall TMain(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TMain *Main;
//---------------------------------------------------------------------------
#endif
