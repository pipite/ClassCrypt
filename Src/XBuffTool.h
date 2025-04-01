#ifndef XBuffToolH
#define XBuffToolH

	std::vector<BYTE> __fastcall UnicodeToBuffer(UnicodeString str);
	UnicodeString     __fastcall BufferToUnicode(const std::vector<BYTE>& buffer);

	UnicodeString     __fastcall BufferToHex(const std::vector<BYTE>& buffer);
	std::vector<BYTE> __fastcall HexToBuffer(UnicodeString hexStr);

	bool              __fastcall BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile);
	std::vector<BYTE> __fastcall FileToBuffer(UnicodeString infile);

	std::vector<BYTE> __fastcall ExtractAESKey(std::vector<BYTE> &buffer);
	bool              __fastcall AddAESKeyToData(std::vector<BYTE> &data, const std::vector<BYTE> &keyBuffer);

	std::string       __fastcall UnicodeToString(const UnicodeString& ustr);

#endif

