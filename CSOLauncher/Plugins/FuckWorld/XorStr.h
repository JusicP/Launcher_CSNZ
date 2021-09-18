#ifndef XOR_STR_H
#define XOR_STR_H

#undef KEY
#undef BUFLEN

template <int XORSTART, int BUFLEN, int XREFKILLER>

class XorStr
{
public:
	XorStr(const char* xs);

#ifndef DEBUG_OPTION
	~XorStr(void)
	{
		for (int i = 0; i < BUFLEN; i++)
			s[i] = 0;
	}
#endif

private: 
	XorStr(void);

public: 
	char s[BUFLEN];
};

template <int XORSTART, int BUFLEN, int XREFKILLER>

XorStr<XORSTART, BUFLEN, XREFKILLER>::XorStr(const char *xs)
{
	int xvalue = XORSTART;

	for (int i = 0; i < (BUFLEN - 1); i++) 
	{
		s[i] = xs[i - XREFKILLER] ^ xvalue;
		xvalue += 1;
		xvalue %= 256;
	}

	s[BUFLEN - 1] = 0;
}

#endif
