#ifndef XBuffToolH
#define XBuffToolH

class XBuffTool {
	public:
				  XBuffTool(void);
				  ~XBuffTool(void);

	std::vector<BYTE> __fastcall UnicodeToBuffer(UnicodeString str);
	UnicodeString     __fastcall BufferToUnicode(const std::vector<BYTE>& buffer);

	UnicodeString     __fastcall BufferToHex(const std::vector<BYTE>& buffer);
	std::vector<BYTE> __fastcall HexToBuffer(UnicodeString hexStr);

	bool              __fastcall BufferToFile(const std::vector<BYTE>& buffer, UnicodeString outfile);
	std::vector<BYTE> __fastcall FileToBuffer(UnicodeString infile);
	
	std::string __fastcall UnicodeToString(const UnicodeString& ustr);

};

#endif

