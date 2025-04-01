#ifndef XAESCryptH
#define XAESCryptH

class XAESCrypt {
	private:

	std::string __fastcall UnicodeToString(const UnicodeString& ustr);

	public:
				  XAESCrypt(void);
				  ~XAESCrypt(void);

	UnicodeString     __fastcall EncryptString(UnicodeString str, HCRYPTKEY key);
	UnicodeString     __fastcall DecryptString(UnicodeString str, HCRYPTKEY key);

	bool 		      __fastcall EncryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key);
	bool 		      __fastcall DecryptFile(UnicodeString infile, UnicodeString outfile, HCRYPTKEY key);

	std::vector<BYTE> __fastcall EncryptBuffer(const std::vector<BYTE>& data, HCRYPTKEY key);
	std::vector<BYTE> __fastcall DecryptBuffer(const std::vector<BYTE>& encryptedData, HCRYPTKEY key);

	std::vector<BYTE> __fastcall UnicodeToBuffer(UnicodeString str);
	UnicodeString     __fastcall BufferToUnicode(const std::vector<BYTE>& buffer);

	UnicodeString     __fastcall BufferToHex(const std::vector<BYTE>& buffer);
	std::vector<BYTE> __fastcall HexToBuffer(UnicodeString hexStr);

	bool              __fastcall BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile);
	std::vector<BYTE> __fastcall FileToBuffer(UnicodeString infile);


	BYTE*             __fastcall RandomAesIVKey(DWORD* keySize);
};

#endif

