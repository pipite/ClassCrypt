#ifndef XRSAKeyH
#define XRSAKeyH

class XRSAKey {
	private:
	HCRYPTPROV hProv;
	HCRYPTKEY  hPrivateKey;
	HCRYPTKEY  hPublicKey;

	bool          __fastcall SaveKeyToFile(const std::string &filename, BYTE *data, DWORD length);
	bool 		  __fastcall LoadKeyFromFile(const std::string &filename, BYTE **buffer, DWORD &length);
	bool 		  __fastcall IsPrivateKey(BYTE* buffer, DWORD length);
	bool 		  __fastcall IsPublicKey(BYTE* buffer, DWORD length);

	public:
				  XRSAKey(void);
				  ~XRSAKey(void);

	void 		  __fastcall ClearKey(void);
	bool          __fastcall GenerateKeyPair(void);
	bool          __fastcall ExtractPublicKey(void);

	bool 		  __fastcall ImportKey(const std::string &filename);

	bool 		  __fastcall ExportPrivateKey(const std::string &filename);
	bool 		  __fastcall ExportPublicKey(const std::string &filename);

	__property HCRYPTPROV Prov       = { read = hProv };
	__property HCRYPTKEY  PrivateKey = { read = hPrivateKey };
	__property HCRYPTKEY  PublicKey  = { read = hPublicKey };

};

#endif

