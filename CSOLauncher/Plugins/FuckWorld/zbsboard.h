class ZBSboard
{
public:
	void Init(void);
	void Redraw(void);

public:
	void BuildNumberRC(wrect_t *rgrc, int w, int h);
	int GetNumWidth(int n, int w, float size = 1);
	void DrawTeamNumber(int n, int x, int y, float size = 1);
	int DrawTeamNumbers(int n, int x, int y, float size = 1);
	void DrawSelfNumber(int n, int x, int y, float size = 1);
	int DrawSelfNumbers(int n, int x, int y, float size = 1);
	void DrawTRecordNumber(int n, int x, int y, float size = 1);
	int DrawTRecordNumbers(int n, int x, int y, float size = 1);
	void SetPlayerScore(int score, int flash);
	void SetTeamScore(int score);
	void SetRoundNums(int nums) { m_iRoundNums = nums; }

private:
	int m_iBackground;
	int m_iTeamnumber;
	wrect_t m_rcTeamnumber[10];
	int m_iSelfnumber;
	wrect_t m_rcSelfnumber[10];
	int m_iToprecord;
	wrect_t m_rcToprecord[10];
	int m_iTeamScore;
	int m_iPlayerScore;
	float m_flFlashSize;
	//float m_flEndFlashTime;
	float m_flStartFlashTime;
	float m_flEndFlashTime;
	int m_iFlashColor[4];
	int m_iRoundNums;
	//float m_flShadeTime;
	float m_flStartShadeTime;
	float m_flEndShadeTime;
	int m_iShadeColor[4];
	int m_iShadeType;
};

extern ZBSboard g_ZBSboard;