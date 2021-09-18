extern int g_SBTopLeft,g_SBTopCenter,g_SBTopRight,g_SBDownLeft,g_SBDownRight,g_SBMode;

class ScoreBoard
{
public:
	void Init(void);
	void Redraw(void);

public:
	int DrawHudsNumber(int x, int y, int iNumber, int r, int g, int b,int length);
	int DrawHudNumber(int x, int y, int iNumber, int r, int g, int b,int length);

private:

	int m_SBHUD_number_0, m_iSBFontWidth, m_iSBFontHeight;
	int m_SBHUD_snumber_0, m_iSBsFontWidth, m_iSBsFontHeight;
	
	int m_iBgNone, m_iBgTd;
	int m_iTextCT, m_iTextTR, m_iTextRound, m_iTextKill;
	int m_iTextHM, m_iTextZB;
	int m_iText1st;
};

extern ScoreBoard g_ScoreBoard;