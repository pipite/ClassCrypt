#ifndef XAESPwdH
#define XAESPwdH

#include "XAESCrypt.h"

class XAESPwd {
	private:
	XAESCrypt     *AESCrypt;
	HCRYPTPROV    hProv;
	HCRYPTKEY     hKey;
	HCRYPTHASH    hHash;
	BYTE          *buffer;
	UnicodeString PPassword;
	bool          PReady;

	std::string   __fastcall UStringToStdString(const UnicodeString& ustr);

	public:
				  XAESPwd(void);
				  ~XAESPwd(void);

	bool 		  __fastcall SetSecurePassword(UnicodeString password);
	void 		  __fastcall ClearKey(void);

	UnicodeString __fastcall EncryptString(UnicodeString str);
	UnicodeString __fastcall DecryptString(UnicodeString str);

	bool          __fastcall EncryptFile(UnicodeString infile, UnicodeString outfile);
	bool          __fastcall DecryptFile(UnicodeString infile, UnicodeString outfile);
};

#endif

