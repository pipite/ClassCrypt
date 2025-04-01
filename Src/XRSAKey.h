#ifndef XRSAKeyH
#define XRSAKeyH

#include "XAESCrypt.h"

class XRSAKey {
	private:
	XAESCrypt *AESCrypt;
	HCRYPTPROV hProv;
	HCRYPTKEY  hPrivateKey;
	HCRYPTKEY  hPublicKey;
	bool PPublicReady;
	bool PPrivateReady;

	bool          __fastcall SaveKeyToFile(const std::string &filename, BYTE *data, DWORD length);
	bool 		  __fastcall LoadKeyFromFile(const std::string &filename, BYTE **buffer, DWORD &length);
	bool 		  __fastcall IsPrivateKey(BYTE* buffer, DWORD length);
	bool 		  __fastcall IsPublicKey(BYTE* buffer, DWORD length);
	bool          __fastcall IsValidPublicKey(void);

	public:
				  XRSAKey(void);
				  ~XRSAKey(void);

	std::string   __fastcall UnicodeToString(const UnicodeString& ustr);

	void 		  __fastcall ClearKey(void);
	bool          __fastcall GenerateKeyPair(void);
	bool          __fastcall ExtractPublicKey(void);

	bool 		  __fastcall ImportKey(const std::string &filename);

	bool 		  __fastcall ExportPrivateKey(const std::string &filename);
	bool 		  __fastcall ExportPublicKey(const std::string &filename);

	UnicodeString __fastcall EncryptString(const UnicodeString& str);
	UnicodeString __fastcall DecryptString(const UnicodeString& hexstr);

	bool 		  __fastcall EncryptFile(const UnicodeString& infile, const UnicodeString& outfile);
	bool 		  __fastcall DecryptFile(const UnicodeString& infile, const UnicodeString& outfile);

	__property HCRYPTPROV Prov         = { read = hProv };
	__property HCRYPTKEY  PrivateKey   = { read = hPrivateKey };
	__property HCRYPTKEY  PublicKey    = { read = hPublicKey };
	__property bool       PrivateReady = { read = PPrivateReady };
	__property bool       PublicReady  = { read = PPublicReady };

};

#endif

