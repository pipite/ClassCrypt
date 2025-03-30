#ifndef XCryptRSAKeyH
#define XCryptRSAKeyH

class XCryptRSAKey {
	private:
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
    HCRYPTKEY  hPublicKey;

	UnicodeString __fastcall BytesToHexString(const std::vector<BYTE>& data);

	public:
				  XCryptRSAKey(void);
				  ~XCryptRSAKey(void);

	UnicodeString __fastcall EncryptStringWithPublicKey(const UnicodeString& input);
};

#endif

