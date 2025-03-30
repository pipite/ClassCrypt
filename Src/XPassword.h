#ifndef XPasswordH
#define XPasswordH

class XPassword {
	private:
	UnicodeString Password;

	UnicodeString __fastcall Shuffle(UnicodeString str);

	public:
				  XPassword(void);
				  ~XPassword(void);

	UnicodeString __fastcall NewSecurePassword(int length);
};

#endif

