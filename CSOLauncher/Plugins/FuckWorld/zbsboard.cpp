#include "base.h"

ZBSboard g_ZBSboard;

#define FLASH_TIME (1.23 / 2.2)

void ZBSboard::Init(void)
{
	m_iBackground = DrawTgaGetID("mode\\zbs\\ZBSboard");
	m_iTeamnumber = DrawTgaGetID("mode\\zbs\\Teamnumber");
	m_iSelfnumber = DrawTgaGetID("mode\\zbs\\Selfnumber");
	m_iToprecord = DrawTgaGetID("mode\\zbs\\Toprecord");

	BuildNumberRC(m_rcTeamnumber, 23, 24);
	BuildNumberRC(m_rcSelfnumber, 18, 19);
	BuildNumberRC(m_rcToprecord, 14, 14);

	m_iTeamScore = 0;
	m_iPlayerScore = 0;
	m_flFlashSize = 1;
	m_iFlashColor[0] = 160;
	m_iFlashColor[1] = 210;
	m_iFlashColor[2] = 250;
	m_iRoundNums = 0;
}

void ZBSboard::Redraw(void)
{
	if (g_iMod != MOD_ZBS)
		return;

	int x, y, w, h;
	int xc, yc;//, wc, hc;
	int wn;//, hn;
	int xe;

	TEXD_BeginDraw();
	TEXD_BindTexture(g_MHTga[m_iBackground].texid);
	TEXD_SetColor(255, 255, 255, 255);

	x = (g_sScreenInfo.iWidth - g_MHTga[m_iBackground].width) / 2;
	y = 5;
	w = g_MHTga[m_iBackground].width;
	h = g_MHTga[m_iBackground].height;

	TEXD_SetRenderMode(kRenderTransTexture);
	TEXD_DrawTexture(x, y, w, h, NULL);

	wn = GetNumWidth(m_iTeamScore, 23);
	xe = GetNumWidth(m_iTeamScore, -2) + 6;
	xc = x + 103 - (wn / 2) + xe;
	yc = y + 10;
	//gEngfuncs.Con_Printf("xc:%d, yc:%d, wn:%d\n", xc, yc, wn);

	// 107 - (wn / 2)
	// 0	: 225 15 23
	// 55	: 213 15 46
	// 110	: 202 15 69

	TEXD_SetColor(255, 255, 255, 255);
	DrawTeamNumbers(m_iTeamScore, xc, yc);

	static float lasttime = g_flTime;
	float frametime = g_flTime - lasttime;

	/*float curtime2 = timeGetTime() / 1000;
	static float lasttime2 = curtime2;
	float frametime2 = curtime2 - lasttime2;*/
	//gEngfuncs.Con_Printf("frametime:%f!!%f\n", frametime, g_flTime);

	//gEngfuncs.Con_Printf("m_flStartFlashTime:%f, m_flEndFlashTime:%f\n", m_flStartFlashTime, m_flEndFlashTime);

	if (m_flEndFlashTime && g_flTime < m_flEndFlashTime && m_flFlashSize > 1)
	{
		float flFlashTime = g_flTime - m_flStartFlashTime;

		//gEngfuncs.Con_Printf("flFlashTime:%f, :%f\n", m_flFlashSize, m_flStartFlashTime);

		if (flFlashTime > 0)
		{
			float flHasDisplayTime = g_flTime - m_flStartFlashTime;
			float flNeedDisplayTime = m_flEndFlashTime - m_flStartFlashTime;
			float rate = float(flHasDisplayTime / flNeedDisplayTime * (0.9));

			//m_flFlashSize -= ((1.9 - 1) * frametime);
			m_flFlashSize = 1.9 - (rate * 1.5);

			//gEngfuncs.Con_NPrintf(0, "time:%f, :%f, rate:%.1f\n", flHasDisplayTime, flNeedDisplayTime, rate);
			//gEngfuncs.Con_Printf("m_flFlashSize:%f, :%f\n", m_flFlashSize, (m_flEndFlashTime - g_flTime));

			float flHasShadeTime = g_flTime - m_flStartShadeTime;
			float flNeedShadeTime = m_flEndShadeTime - m_flStartShadeTime;
			float rate2 = float(flHasShadeTime / flNeedShadeTime * (1));

			//gEngfuncs.Con_Printf("m_iShadeType:%d, m_flShadeTime:%.1f, color{%d, %d, %d}, rate:%.1f\n", m_iShadeType, flHasShadeTime, m_iFlashColor[0], m_iFlashColor[1], m_iFlashColor[2], rate2);

			if (m_iShadeType == 0)
			{
				if (m_flEndShadeTime && g_flTime < m_flEndShadeTime)
				{
					int r = 160 - m_iFlashColor[0]; // Blue
					int g = 210 - m_iFlashColor[1];
					int b = 250 - m_iFlashColor[2];

					m_iFlashColor[0] = 240 + rate2 * r; // Yellow
					m_iFlashColor[1] = 200 + rate2 * g;
					m_iFlashColor[2] = 50 + rate2 * b;
				}
				else
				{
					m_flStartShadeTime = g_flTime;
					m_flEndShadeTime = m_flStartShadeTime + (FLASH_TIME / 4);
					m_iShadeType = 1;
				}
			}
			else if (m_iShadeType == 1)
			{
				if (m_flEndShadeTime && g_flTime < m_flEndShadeTime)
				{
					int r = 150 - m_iFlashColor[0]; // Green
					int g = 210 - m_iFlashColor[1];
					int b = 10 - m_iFlashColor[2];

					m_iFlashColor[0] = 160 + rate2 * r; // Blue
					m_iFlashColor[1] = 210 + rate2 * g;
					m_iFlashColor[2] = 250 + rate2 * b;
				}
				else
				{
					m_flStartShadeTime = g_flTime;
					m_flEndShadeTime = m_flStartShadeTime + (FLASH_TIME / 4);
					m_iShadeType = 2;
				}
			}
			else if (m_iShadeType == 2)
			{
				if (m_flEndShadeTime && g_flTime < m_flEndShadeTime)
				{
					int r = 160 - m_iFlashColor[0]; // Blue
					int g = 210 - m_iFlashColor[1];
					int b = 250 - m_iFlashColor[2];

					m_iFlashColor[0] = 150 + rate2 * r; // Green
					m_iFlashColor[1] = 210 + rate2 * g;
					m_iFlashColor[2] = 10 + rate2 * b;
				}
				else
				{
					m_flEndShadeTime = 0;
					m_iShadeType = 4;
				}
			}
			/*else if (m_iShadeType == 3)
			{
				if (m_flEndShadeTime && g_flTime < m_flEndShadeTime)
				{
					int r = 240 - m_iFlashColor[0];
					int g = 200 - m_iFlashColor[1];
					int b = 50 - m_iFlashColor[2];

					m_iFlashColor[0] = 160 + rate2 * r;
					m_iFlashColor[1] = 210 + rate2 * g;
					m_iFlashColor[2] = 250 + rate2 * b;
				}
				else
				{
					m_flEndShadeTime = 0;
					m_iShadeType = 4;
				}
			}*/
		}
	}
	else
	{
		m_flEndFlashTime = 0;
		m_iFlashColor[0] = 160;
		m_iFlashColor[1] = 210;
		m_iFlashColor[2] = 250;
		m_flFlashSize = 1;
	}

	lasttime = g_flTime;
	//lasttime2 = curtime2;

	wn = GetNumWidth(m_iPlayerScore, 18 + 4, m_flFlashSize);
	//xc = x + 245 + 48 + 4 - (wn / 2);
	xc = x + 297 - (wn / 2) + ((m_iPlayerScore != 0) ? 1 : 0);
	yc = y + 23 - (19 * m_flFlashSize / 2);

	//TEXD_SetColor(160, 210, 250, 255);
	//TEXD_SetColor(240, 200, 50, 255);
	TEXD_SetColor(m_iFlashColor[0], m_iFlashColor[1], m_iFlashColor[2], 255);
	DrawSelfNumbers(m_iPlayerScore, xc, yc, m_flFlashSize);

	wn = GetNumWidth(m_iRoundNums, 14 + 4);
	xc = x + 212 + 2 - (wn / 2);
	yc = y + 27 + 2;

	TEXD_SetColor(255, 255, 255, 255);
	DrawTRecordNumbers(m_iRoundNums, xc, yc);

	TEXD_EndDraw();
}

void ZBSboard::BuildNumberRC(wrect_t *rgrc, int w, int h)
{
	int nw = 0;
	int nh = 0;

	for (int i = 0; i < 10; i++)
	{
		rgrc[i].left = nw;
		rgrc[i].top = 0;
		rgrc[i].right = rgrc[i].left + w;
		rgrc[i].bottom = h;

		nw += w;
		nh += h;
	}
}

void ZBSboard::DrawTeamNumber(int n, int x, int y, float size)
{
	TEXD_BindTexture(g_MHTga[m_iTeamnumber].texid);
	TEXD_DrawTexture(x, y, 230, 24, &m_rcTeamnumber[n], size);
}

int ZBSboard::GetNumWidth(int n, int w, float size)
{
	w *= size;

	int width = 0;

	if (n < 0)
		return w;

	if (n >= 10000)
		width += w;

	if (n >= 1000)
		width += w;

	if (n >= 100)
		width += w;

	if (n >= 10)
		width += w;

	width += w;
	return width;
}

int ZBSboard::DrawTeamNumbers(int n, int x, int y, float size)
{
	int width = 23 + 4;
	width *= size;

	if (n < 0)
		return x;

	int k;

	if (n >= 10000)
	{
		k = n / 10000;
		DrawTeamNumber(k, x, y, size);
		x += width;
	}

	if (n >= 1000)
	{
		k = (n % 10000) / 1000;
		DrawTeamNumber(k, x, y, size);
		x += width;
	}

	if (n >= 100)
	{
		k = (n % 1000) / 100;
		DrawTeamNumber(k, x, y, size);
		x += width;
	}

	if (n >= 10)
	{
		k = (n % 100) / 10;
		DrawTeamNumber(k, x, y, size);
		x += width;
	}

	k = n % 10;
	DrawTeamNumber(k, x, y, size);
	x += width;
	return x;
}

void ZBSboard::DrawSelfNumber(int n, int x, int y, float size)
{
	TEXD_BindTexture(g_MHTga[m_iSelfnumber].texid);
	TEXD_DrawTexture(x, y, 180, 19, &m_rcSelfnumber[n], size);
}

int ZBSboard::DrawSelfNumbers(int n, int x, int y, float size)
{
	int width = 18 + 4;
	width *= size;

	if (n < 0)
		return x;

	int k;

	if (n >= 10000)
	{
		k = n / 10000;
		DrawSelfNumber(k, x, y, size);
		x += width;
	}

	if (n >= 1000)
	{
		k = (n % 10000) / 1000;
		DrawSelfNumber(k, x, y, size);
		x += width;
	}

	if (n >= 100)
	{
		k = (n % 1000) / 100;
		DrawSelfNumber(k, x, y, size);
		x += width;
	}

	if (n >= 10)
	{
		k = (n % 100) / 10;
		DrawSelfNumber(k, x, y, size);
		x += width;
	}

	k = n % 10;
	DrawSelfNumber(k, x, y, size);
	x += width;
	return x;
}

void ZBSboard::DrawTRecordNumber(int n, int x, int y, float size)
{
	TEXD_BindTexture(g_MHTga[m_iToprecord].texid);
	TEXD_DrawTexture(x, y, 140, 14, &m_rcToprecord[n], size);
}

int ZBSboard::DrawTRecordNumbers(int n, int x, int y, float size)
{
	int width = 14 + 4;
	width *= size;

	if (n < 0)
		return x;

	int k;

	if (n >= 1000)
	{
		k = n / 1000;
		DrawTRecordNumber(k, x, y, size);
		x += width;
	}

	if (n >= 100)
	{
		k = (n % 1000) / 100;
		DrawTRecordNumber(k, x, y, size);
		x += width;
	}

	if (n >= 10)
	{
		k = (n % 100) / 10;
		DrawTRecordNumber(k, x, y, size);
		x += width;
	}

	k = n % 10;
	DrawTRecordNumber(k, x, y, size);
	x += width;
	return x;
}

void ZBSboard::SetPlayerScore(int score, int flash)
{
	m_iPlayerScore = score;

	if (flash)
	{
		m_flStartFlashTime = g_flTime;
		m_flEndFlashTime = m_flStartFlashTime + FLASH_TIME;
		m_flFlashSize = 1.9;

		m_iFlashColor[0] = 240;
		m_iFlashColor[1] = 200;
		m_iFlashColor[2] = 50;

		m_iShadeColor[0] = 150;
		m_iShadeColor[1] = 210;
		m_iShadeColor[2] = 10;

		m_flStartShadeTime = g_flTime;
		m_flEndShadeTime = m_flStartShadeTime + (FLASH_TIME / 4);

		//m_flShadeTime = (FLASH_TIME / 2);
		m_iShadeType = 0;
	}
}

void ZBSboard::SetTeamScore(int score)
{
	m_iTeamScore = score;
}