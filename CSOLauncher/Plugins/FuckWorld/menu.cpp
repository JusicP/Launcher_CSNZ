#include "base.h"

char g_Menu_text[1024];

float g_Menu_Drawing_time;
int g_Menu_Can_Press[10];
int iLine;
int iHeight = 0,iWidth = 0;

void DrawMenu(void)
{
	if(g_isShowingZbMenu && pCvar_ZombieMenu->value) return;
	if(!g_Menu_Drawing || !pCvar_DrawMenu->value) return;

	int alpha = 255;
	if(g_flTime - g_Menu_Drawing_time <0.2)
	{
		if(g_Menu_Drawing==2)
			alpha = 255 - (g_flTime - g_Menu_Drawing_time) / 0.2 * 255;			
		else
			alpha = (g_flTime - g_Menu_Drawing_time) / 0.2 * 255;
	}
	else
	{
		if(g_Menu_Drawing==2)
			g_Menu_Drawing = 0;
		else			
			alpha = 255;			
	}

	if(!g_Menu_Drawing) return;	

	int iLineEnd = 0, iLineStart = 0;
	char szPrint[1024];		
	szPrint[1023] = 0;

	int iX, iY;
	iY = (g_sScreenInfo.iHeight - iLine * 15) / 2;
	iX = 20;
	iHeight = iLine * 16 + 20;

	MH_DrawTGA_9(g_UI_Panel, iX - 10, iY - 10, iWidth, iHeight, alpha);

	if(g_flTime - g_Menu_Drawing_time >0.1 && g_flTime - g_Menu_Drawing_time <0.2 && g_Menu_Drawing==2)
		return;
	
	bool hit = false;
	bool drawed = false;
	int clr=0;
	
	for (iLineEnd = 0; iLineEnd < 1023 && g_Menu_text[iLineEnd] != '\0'; iLineEnd++)
	{
		if (g_Menu_text[iLineStart+1] == 'r' && g_Menu_text[iLineStart] == '\\')	clr=1;
		else if (g_Menu_text[iLineStart+1] == 'd' && g_Menu_text[iLineStart] == '\\')	clr=2;
		else if (g_Menu_text[iLineStart+1] == 'y' && g_Menu_text[iLineStart] == '\\')	clr=3;
		else if (g_Menu_text[iLineStart+1] == 'w' && g_Menu_text[iLineStart] == '\\')	clr=4;

		if((g_Menu_text[iLineEnd] == '\\' && (g_Menu_text[iLineEnd+1] == 'r' || g_Menu_text[iLineEnd+1] == 'd' || g_Menu_text[iLineEnd+1] == 'y' || g_Menu_text[iLineEnd+1] == 'w')) || g_Menu_text[iLineEnd] == '\n')
		{
			if(g_Menu_text[iLineStart] == '\\' && (g_Menu_text[iLineStart+1] == 'r' || g_Menu_text[iLineStart+1] == 'd' || g_Menu_text[iLineStart+1] == 'y' || g_Menu_text[iLineStart+1] == 'w'))
			{
				if(iLineEnd - iLineStart - 2 >= 0)
					iLineStart += 2;
			}

			memset(szPrint,0,1024);
			strncpy(szPrint, g_Menu_text + iLineStart, iLineEnd - iLineStart);
			iLineStart = iLineEnd;

			if (clr==1)	gEngfuncs.pfnDrawSetTextColor(1.0, 0.3, 0.3);
			else if (clr==2) gEngfuncs.pfnDrawSetTextColor(0.4, 0.4, 0.4);
			else if (clr==3) gEngfuncs.pfnDrawSetTextColor(1.0, 0.93, 0.3);
			else if (clr==4) gEngfuncs.pfnDrawSetTextColor(0.95, 0.95, 0.95);

			gEngfuncs.pfnDrawConsoleString(iX, iY+3, szPrint);
			int iLength, iHeight;
			gEngfuncs.pfnDrawConsoleStringLen(szPrint,&iLength,&iHeight);
			szPrint[strlen(szPrint)] = 0;

			//if(szPrint[0] != 10 && szPrint[1] != 0)
				iX += iLength;

			if(szPrint[0] == 10)
				iX -= 8;

		}
	
		if (g_Menu_text[iLineEnd] == '\n')
		{
			iY += 16;
			iX = 20;
		}
	

	}

}


void GetHeightWidth(void)
{
	int iLineEnd = 0, iLineStart = 0, iLength = 0, iLength2 = 0, iLength3 = 0;
	char szPrint[1024];	
	char num[3];
	char str[8];
	

	iLine = 0;
	iWidth = 0;

	for (int i=1;i<=9;i++) g_Menu_Can_Press[i] = 0;
	g_Menu_Can_Press[0] = 1;
	for (int iLineEnd = 0; iLineEnd < 1024 && g_Menu_text[iLineEnd] != '\0'; iLineEnd++)
	{
		if (g_Menu_text[iLineEnd+1] == 'r' && g_Menu_text[iLineEnd] == '\\')
		{
			gEngfuncs.pfnDrawConsoleStringLen("\r",&iLength3,&iHeight);
			iLength2 += iLength3;
		}
		else if (g_Menu_text[iLineEnd+1] == 'y' && g_Menu_text[iLineEnd] == '\\')
		{
			gEngfuncs.pfnDrawConsoleStringLen("\y",&iLength3,&iHeight);
			iLength2 += iLength3;
		}
		else if (g_Menu_text[iLineEnd+1] == 'w' && g_Menu_text[iLineEnd] == '\\')
		{
			gEngfuncs.pfnDrawConsoleStringLen("\w",&iLength3,&iHeight);
			iLength2 += iLength3;
		}
		/*else if (g_Menu_text[iLineEnd+1] == 'd' && g_Menu_text[iLineEnd] == '\\')
		{
			gEngfuncs.pfnDrawConsoleStringLen("\d",&iLength3,&iHeight);
			iLength2 += iLength3;
		}*/

		if (g_Menu_text[iLineEnd] == '\n')
		{
			iLine += 1;
			memset(szPrint,0,1024);
			strncpy(szPrint, g_Menu_text + iLineStart, iLineEnd - iLineStart);

			gEngfuncs.pfnDrawConsoleStringLen(szPrint,&iLength,&iHeight);
			iLineStart = iLineEnd;
			iLength = iLength - iLength2;
			iLength2 = 0;
			if (iLength > iWidth) iWidth = iLength;

			if (strlen(szPrint)>2 && iLine > 1)
			{
				for (int i=1;i<=9;i++)
				{					
					strncpy(str, szPrint, 8);
					str[7] = 0;
					sprintf(num, "%d.",i);
					if (strstr(str,num) && !strstr(str,"\d"))
						g_Menu_Can_Press[i] = 1;
				}
			}

		}
	}

	iWidth += 20;
	
}



// 下面是抄nagi的 (其实是HLSDK里的啦)
char *BufferedLocaliseTextString(const char *msg)
{
	static char dst_buffer[1024];
	
	LocaliseTextString(msg, dst_buffer, 1024);
	return dst_buffer;
}
char *LocaliseTextString(const char *msg, char *dst_buffer, int buffer_size)
{
	char *dst = dst_buffer;

	for (char *src = (char*)msg; *src != 0 && buffer_size > 0; buffer_size--)
	{
		if (*src == '#')
		{
			static char word_buf[255];
			char *wdst = word_buf, *word_start = src;

			for (++src ; (*src >= 'A' && *src <= 'z') || (*src >= '0' && *src <= '9'); wdst++, src++)
				*wdst = *src;

			*wdst = 0;

			client_textmessage_t *clmsg = TextMessageGet(word_buf);

			if (!clmsg || !(clmsg->pMessage))
			{
				src = word_start;
				*dst = *src;
				dst++, src++;
				continue;
			}

			for (char *wsrc = (char*)clmsg->pMessage; *wsrc != 0; wsrc++, dst++)
				*dst = *wsrc;

			*dst = 0;
		}
		else
		{
			*dst = *src;
			dst++, src++;
			*dst = 0;
		}
	}

	dst_buffer[buffer_size - 1] = 0;
	return dst_buffer;
}
