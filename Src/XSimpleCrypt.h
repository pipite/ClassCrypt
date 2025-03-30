#ifndef XSimpleCryptH
#define XSimpleCryptH

class XSimpleCrypt {
	private:
	char          __fastcall RandomChar(void);

	public:
				  XSimpleCrypt(void);
				  ~XSimpleCrypt(void);

	// Methode 1 : Simple et reversible
	UnicodeString __fastcall Encode(UnicodeString pw);

	// Methode 2 : Simple non reversible
	UnicodeString __fastcall Encrypt(UnicodeString pw);
	UnicodeString __fastcall Decrypt(UnicodeString pw);
};

#endif

