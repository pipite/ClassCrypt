#ifndef XCryptRSAPwdH
#define XCryptRSAPwdH

class XCryptRSAPwd {
	private:
	HCRYPTPROV    hProv;
	HCRYPTKEY     hKey;
	HCRYPTHASH    hHash;
	BYTE          *buffer;
	UnicodeString PPassword;
	bool          PReady;

	std::string   __fastcall UStringToStdString(const UnicodeString& ustr);

	public:
				  XCryptRSAPwd(void);
				  ~XCryptRSAPwd(void);

	bool 		  __fastcall SetPassword(UnicodeString password);
	void 		  __fastcall ClearKey(void);

	UnicodeString __fastcall EncryptString(UnicodeString str);
	UnicodeString __fastcall DecryptString(UnicodeString str);

	bool          __fastcall EncryptFile(UnicodeString infile, UnicodeString outfile);
	bool          __fastcall DecryptFile(UnicodeString infile, UnicodeString outfile);
};

#endif

