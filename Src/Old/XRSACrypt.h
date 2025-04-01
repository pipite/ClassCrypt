#ifndef XRSACryptH
#define XRSACryptH

#include "XRSAKey.h"

class XRSACrypt {
	private:

	std::string __fastcall UnicodeToString(const UnicodeString& ustr);

	public:
				  XRSACrypt(void);
				  ~XRSACrypt(void);

	UnicodeString __fastcall EncryptString(UnicodeString str, HCRYPTKEY key);
	UnicodeString __fastcall DecryptString(UnicodeString str, HCRYPTKEY key);

	bool 		  __fastcall EncryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key);
	bool 		  __fastcall DecryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key);
};

#endif

