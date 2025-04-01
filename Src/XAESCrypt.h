#ifndef XAESCryptH
#define XAESCryptH

#include "XBuffTool.h"

class XAESCrypt {
	private:
//	HCRYPTPROV hTempProv;

	public:
				  XAESCrypt(void);
				  ~XAESCrypt(void);

	UnicodeString     __fastcall EncryptString(UnicodeString str, HCRYPTKEY key);
	UnicodeString     __fastcall DecryptString(UnicodeString str, HCRYPTKEY key);

	bool 		      __fastcall EncryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key);
	bool 		      __fastcall DecryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key);

	std::vector<BYTE> __fastcall EncryptBuffer(const std::vector<BYTE>& data, HCRYPTKEY key);
	std::vector<BYTE> __fastcall DecryptBuffer(const std::vector<BYTE>& encryptedData, HCRYPTKEY key);

	bool              __fastcall ImportAesKey(HCRYPTPROV &prov, HCRYPTKEY &key, const std::vector<BYTE>& keyBlob);
	std::vector<BYTE> __fastcall ExportAesKey(HCRYPTKEY hAesKey);

	bool              __fastcall NewRandomAesKey(HCRYPTPROV &prov, HCRYPTKEY &key);
	HCRYPTKEY         __fastcall GenerateSecurePasswordAesKey(UnicodeString password);
};

#endif

