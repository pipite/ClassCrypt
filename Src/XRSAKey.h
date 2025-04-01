#ifndef XRSAKeyH
#define XRSAKeyH

#include "XAESCrypt.h"
#include <vector>

class XRSAKey {
	private:
	XAESCrypt *AESCrypt;
	HCRYPTPROV hProv;
	HCRYPTKEY  hPrivateKey;
	HCRYPTKEY  hPublicKey;
	bool PPublicReady;
	bool PPrivateReady;

	bool          __fastcall SaveKeyToFile(const std::string &filename, const std::vector<BYTE> &data);
	bool 		  __fastcall LoadKeyFromFile(const std::string &filename, std::vector<BYTE> &buffer);
	bool 		  __fastcall IsPrivateKey(const std::vector<BYTE> &buffer);
	bool 		  __fastcall IsPublicKey(const std::vector<BYTE> &buffer);
	bool          __fastcall IsValid(const std::vector<BYTE> &buffer);

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

