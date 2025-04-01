#ifndef XCryptRSAKeyH
#define XCryptRSAKeyH

#include "XRSAKey.h"

class XCryptRSAKey {
	private:
	XRSAKey *RSAKey;

	public:
				  XCryptRSAKey(void);
				  ~XCryptRSAKey(void);

	void          __fastcall SetRSAKey(XRSAKey *rsakey);

	UnicodeString __fastcall EncryptString(const UnicodeString& input);
	UnicodeString __fastcall DecryptString(const UnicodeString& hexInput);

	bool          __fastcall EncryptFile(const UnicodeString& infile, const UnicodeString& outfile);
	bool          __fastcall DecryptFile(const UnicodeString& infile, const UnicodeString& outfile);
};

#endif

