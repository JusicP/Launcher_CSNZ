#include "base.h"
#define CLASS_IMAGE	1
#define CLASS_LABEL	2
#define CLASS_BUTTON	3
#define CLASS_EXTRA_BUTTON	4
#define CLASS_DEFINE	5
#define CLASS_CHECKBOX	6
#define CLASS_LINE	7
#define MGUI_DEBUG

#define MGUI_ITEMS_MAX	64
struct MGUIElement
{
	int iFileID;
	char sName[32];
	int iClass;
	int Xpos,Ypos,Width,Height;
	int iAutoResize; // share for checkbox
	int iTexID;
	int iSize;
	int r,g,b,a;
	int iFollowMouse;
	char sPic[32];
	int iID;
	char sCmd[32];
	char sMGUI[32];
	int iDefine; 
}g_MGUI_MAX[512];
struct MGUIFileInfo
{
	int iStartID;
	int iEndID;
}g_MGUI_File[100];
struct MGUITypeDef
{
	int iClass;
	int iImage[9];
	char Name[32];
	int iLeft,iRight,iHeight;
}g_MGUI_TypeDef[10];

int g_mgui_bg;
int g_mgui_count = -1; // from 0
int g_mgui_mouseevent = 0;
int g_mgui_file_count = 0; // from 1
char g_mgui_file[20][32]; 
int g_mgui_def_count = 0;

int g_mgui_file_drawing = 0;
int g_mgui_candraw = 0;
int g_mgui_file_extra_drawing = 0;

int g_mgui_tga_checkbox_on=0;
int g_mgui_tga_checkbox_off=0;

extern float g_mgui_nextclicktime = 0;

void MGUI_Init(void)
{
	g_mgui_tga_checkbox_on = DrawTgaGetID("checkbox_on");
	g_mgui_tga_checkbox_off = DrawTgaGetID("checkbox_off");
}


int MGUI_ReSortElements(int iFileID)
{
	// 获取信息
	int iStart = g_MGUI_File[iFileID].iStartID;
	int iEnd = g_MGUI_File[iFileID].iEndID;
	int iTotal = iEnd - iStart +1;
	int iBegin = iStart;
	// 清除掉信息
	for(int i=0;i<iTotal;i++)
	{
		memset(&g_MGUI_MAX[iBegin],0,sizeof(MGUIElement));
		iBegin++;
	}
	// 搜索后面的前移
	iBegin = iEnd+1;
	iTotal = g_mgui_count - iEnd;
	for(int i=iEnd+1;i<iTotal;i++)
	{
		memcpy(&g_MGUI_MAX[iStart],&g_MGUI_MAX[iBegin],sizeof(MGUIElement));
		memset(&g_MGUI_MAX[iBegin],0,sizeof(MGUIElement));
		iBegin ++;
		iStart ++;
	}
	iTotal = g_MGUI_File[iFileID].iEndID - g_MGUI_File[iFileID].iStartID +1;
	g_mgui_count -= iTotal;
	LogToFile("删除相同文件元素::文件ID:%d 开始/结束元素ID:%d/%d 删除的元素:%d剩余元素:%d",iFileID,g_MGUI_File[iFileID].iStartID,g_MGUI_File[iFileID].iEndID,iTotal,g_mgui_count);
	return g_mgui_count;
}

int IsInRect(int iMouseX,int iMouseY,int x,int y,int w,int h)
{
	if( iMouseX>x && iMouseX< x+w && iMouseY>y && iMouseY<y+h) return 1;
	return 0;
}
void MGUI_WriteMGUI(FILE *pFile,char *Section, char *Content)
{
	fprintf(pFile,"[%s]\n",Section);
	fprintf(pFile,"%s\n",Content);
}
int MGUI_RunScript(char *pCmd)
{
	// 暂时是CVAR
	cvar_s *pCvar = gEngfuncs.pfnGetCvarPointer(pCmd);
	if(!pCvar) return -1;
	return pCvar->value;
}
void MGUI_Test(void)
{
	static int iDrawToggle=0;
	static int iExtraButtonActive;
	static int iOldButton = 0;
	iExtraButtonActive = 0;
	if(iDrawToggle != g_mgui_candraw) 
	{
		if(g_mgui_candraw) gExportfuncs.IN_DeactivateMouse();
		else if(!g_mgui_candraw) gExportfuncs.IN_ActivateMouse();
		iDrawToggle = g_mgui_candraw;
	}
	if(!g_mgui_candraw || !g_mgui_file_drawing) return;
	
	gExportfuncs.IN_DeactivateMouse();

	static int iMouseX,iMouseY;
	int iStore = 0;
	int iStoreX,iStoreY;
	gEngfuncs.GetMousePosition( &iMouseX,&iMouseY);

	#ifdef MGUI_DEBUG
	
	char szPrint[64];
	sprintf(szPrint,"ENGINE API X:%d Y:%d Event:%d",iMouseX,iMouseY,g_mgui_mouseevent);
	gEngfuncs.pfnDrawConsoleString(100,10,szPrint);
#endif

 
	for(int i = 0;i<=g_mgui_count ;i++)
	{
		if(g_mgui_file_extra_drawing && g_mgui_file_extra_drawing != g_MGUI_MAX[i].iFileID && g_mgui_file_drawing != g_MGUI_MAX[i].iFileID) continue;
		else if(!g_mgui_file_extra_drawing && g_mgui_file_drawing != g_MGUI_MAX[i].iFileID) continue;

		if(g_mgui_file_extra_drawing && g_mgui_file_extra_drawing == g_MGUI_MAX[i].iFileID && g_MGUI_MAX[i].iFollowMouse) // change pos
		{
			iStore = 1;
			iStoreX = g_MGUI_MAX[i].Xpos;
			iStoreY = g_MGUI_MAX[i].Ypos;

			g_MGUI_MAX[i].Xpos = g_MGUI_MAX[i].Xpos + iMouseX;
			g_MGUI_MAX[i].Ypos = g_MGUI_MAX[i].Ypos + iMouseY;
		}

		if(g_MGUI_MAX[i].iClass == CLASS_IMAGE)
		{
			if( !g_MGUI_MAX[i].iAutoResize)
			{
				MH_DrawTGAFunction(g_MGUI_MAX[i].iTexID,255,255,255,255,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,1.0);
			}
			else
			{
				MH_DrawTGAFunction2(g_MGUI_MAX[i].iTexID,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MGUI_MAX[i].Width,g_MGUI_MAX[i].Height);
			}
		}
		else if(g_MGUI_MAX[i].iClass == CLASS_LABEL)
		{
			Fonts_SetSize(g_MGUI_MAX[i].iSize,g_MGUI_MAX[i].iSize);
			Fonts_SetColor(g_MGUI_MAX[i].r,g_MGUI_MAX[i].g,g_MGUI_MAX[i].b,g_MGUI_MAX[i].a);
			Fonts_Draw(UTF8ToUnicode(g_MGUI_MAX[i].sPic),g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,2000,2000);
		}
		else if(g_MGUI_MAX[i].iClass == CLASS_LINE)
		{
			gEngfuncs.pfnFillRGBA(g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MGUI_MAX[i].Width,g_MGUI_MAX[i].Height,g_MGUI_MAX[i].r,g_MGUI_MAX[i].g,g_MGUI_MAX[i].b,g_MGUI_MAX[i].a);
		}
		else if(g_MGUI_MAX[i].iClass == CLASS_CHECKBOX)
		{
			int iCall = MGUI_RunScript(g_MGUI_MAX[i].sCmd);
			g_MGUI_MAX[i].iAutoResize = iCall;
			if(IsInRect(iMouseX,iMouseY,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MHTga[g_mgui_tga_checkbox_off].width,g_MHTga[g_mgui_tga_checkbox_off].height))
			{
				if(iOldButton && !g_mgui_mouseevent && g_mgui_nextclicktime < g_flTime) 
				{
					g_mgui_nextclicktime = g_flTime + 0.4f;
					g_MGUI_MAX[i].iAutoResize = !g_MGUI_MAX[i].iAutoResize;
					char cmd[64];
					sprintf(cmd,"%s %d",g_MGUI_MAX[i].sCmd,g_MGUI_MAX[i].iAutoResize);
					gEngfuncs.pfnClientCmd(cmd);
				}
			}
			if(g_MGUI_MAX[i].iAutoResize)
			{
				MH_DrawTGAFunction2(g_mgui_tga_checkbox_on,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MHTga[g_mgui_tga_checkbox_on].width,g_MHTga[g_mgui_tga_checkbox_on].height);
			}
			else
			{
				MH_DrawTGAFunction2(g_mgui_tga_checkbox_off,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MHTga[g_mgui_tga_checkbox_off].width,g_MHTga[g_mgui_tga_checkbox_off].height);
			}
		}
		else if(g_MGUI_MAX[i].iClass == CLASS_BUTTON)
		{
			Fonts_SetSize(g_MGUI_MAX[i].iSize,g_MGUI_MAX[i].iSize);
			// 检测是否在矩形内 
			
			MH_DrawTGAFunction2(g_MGUI_MAX[i].iTexID,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MGUI_MAX[i].Width,g_MGUI_MAX[i].Height);
			if(IsInRect(iMouseX,iMouseY,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MGUI_MAX[i].Width,g_MGUI_MAX[i].Height))
			{	
				Fonts_SetColor(0,0,0,255);
				if(g_mgui_mouseevent == 1) Fonts_SetColor(255,0,0,255);
				if(iOldButton && !g_mgui_mouseevent && g_mgui_nextclicktime < g_flTime) 
				{
					Fonts_SetColor(255,0,0,255);
					g_mgui_nextclicktime = g_flTime + 0.4f;
					// 检测命令是发送Command到服务器 还是打开新MGUI
					if(strstr(g_MGUI_MAX[i].sCmd,".mgui"))
					{
						LogToFile("MGUI命令执行::%s",g_MGUI_MAX[i].sCmd);
						g_mgui_file_drawing = MGUI_ReadFromResourceFile(g_MGUI_MAX[i].sCmd);
						
					}
					else 
					{
						gEngfuncs.pfnClientCmd(g_MGUI_MAX[i].sCmd);
						// Close MGUI
						g_mgui_candraw = 0;
					}
				}
			}
			else Fonts_SetColor(255,255,255,255);
			// 计算文字位置 保证在按钮中居中
			int iXOffset,iYOffset;
			int iLen = Fonts_GetLen(UTF8ToUnicode(g_MGUI_MAX[i].sPic));
			iXOffset = (g_MGUI_MAX[i].Width - iLen)/2;
			iYOffset = (g_MGUI_MAX[i].Height - g_MGUI_MAX[i].iSize)/2.5;
			Fonts_Draw(UTF8ToUnicode(g_MGUI_MAX[i].sPic),g_MGUI_MAX[i].Xpos+iXOffset,g_MGUI_MAX[i].Ypos+g_MGUI_MAX[i].iSize+iYOffset,2000,2000);
		}
		else if(g_MGUI_MAX[i].iClass == CLASS_EXTRA_BUTTON)
		{
			Fonts_SetSize(g_MGUI_MAX[i].iSize,g_MGUI_MAX[i].iSize);
			// 检测是否在矩形内
			MH_DrawTGAFunction2(g_MGUI_MAX[i].iTexID,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MGUI_MAX[i].Width,g_MGUI_MAX[i].Height);
			if(IsInRect(iMouseX,iMouseY,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MGUI_MAX[i].Width,g_MGUI_MAX[i].Height))
			{
				Fonts_SetColor(0,0,0,255);
				if(g_mgui_mouseevent == 1) Fonts_SetColor(255,0,0,255);
				if(iOldButton && !g_mgui_mouseevent && g_mgui_nextclicktime < g_flTime) 
				{
					Fonts_SetColor(255,0,0,255);
					g_mgui_nextclicktime = g_flTime + 0.5f;
					// 检测命令是发送Command到服务器 还是打开新MGUI
					if(strstr(g_MGUI_MAX[i].sCmd,".mgui"))
					{
						g_mgui_file_drawing = MGUI_ReadFromResourceFile(g_MGUI_MAX[i].sCmd);
					}
					else 
					{
						gEngfuncs.pfnClientCmd(g_MGUI_MAX[i].sCmd);
						g_mgui_candraw = 0;
					}
				}
				iExtraButtonActive = 1;
				g_mgui_file_extra_drawing = MGUI_ReadFromResourceFile(g_MGUI_MAX[i].sMGUI);
			}
			else Fonts_SetColor(255,255,255,255);
			// 计算文字位置 保证在按钮中居中
			int iXOffset,iYOffset;
			int iLen = Fonts_GetLen(UTF8ToUnicode(g_MGUI_MAX[i].sPic));
			iXOffset = (g_MGUI_MAX[i].Width - iLen)/2;
			iYOffset = (g_MGUI_MAX[i].Height - g_MGUI_MAX[i].iSize)/2.5;
			Fonts_Draw(UTF8ToUnicode(g_MGUI_MAX[i].sPic),g_MGUI_MAX[i].Xpos+iXOffset,g_MGUI_MAX[i].Ypos+g_MGUI_MAX[i].iSize+iYOffset,2000,2000);
		}
		else if(g_MGUI_MAX[i].iClass == CLASS_DEFINE && g_MGUI_MAX[i].iDefine)
		{
			if(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iClass == 1) // button
			{
				// BUTTON == 0 -- origin 1 -- mouseover 2 -- click
				if(IsInRect(iMouseX,iMouseY,g_MGUI_MAX[i].Xpos,g_MGUI_MAX[i].Ypos,g_MGUI_MAX[i].Width,g_MGUI_MAX[i].Height))
				{
					// 鼠标进入区域
					if(g_mgui_mouseevent == 1)
					{
						//鼠标保持按下
						int iCenter = g_MGUI_MAX[i].Width - g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft - g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iRight;
						int iStartX = g_MGUI_MAX[i].Xpos;
						MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[6],iStartX,g_MGUI_MAX[i].Ypos,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
						iStartX += g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft;
						MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[7],iStartX,g_MGUI_MAX[i].Ypos,iCenter,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
						iStartX += iCenter;
						MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[8],iStartX,g_MGUI_MAX[i].Ypos,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iRight,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
					}
					else
					{
						// 鼠标悬停
						int iCenter = g_MGUI_MAX[i].Width - g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft - g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iRight;
						int iStartX = g_MGUI_MAX[i].Xpos;
						MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[3],iStartX,g_MGUI_MAX[i].Ypos,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
						iStartX += g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft;
						MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[4],iStartX,g_MGUI_MAX[i].Ypos,iCenter,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
						iStartX += iCenter;
						MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[5],iStartX,g_MGUI_MAX[i].Ypos,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iRight,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
					}
					if(iOldButton && !g_mgui_mouseevent && g_mgui_nextclicktime < g_flTime) 
					{
						g_mgui_nextclicktime = g_flTime + 1.0f;
						// 检测命令是发送Command到服务器 还是打开新MGUI
						if(strstr(g_MGUI_MAX[i].sCmd,".mgui"))
						{
							LogToFile("MGUI命令执行::%s",g_MGUI_MAX[i].sCmd);
							g_mgui_file_drawing = MGUI_ReadFromResourceFile(g_MGUI_MAX[i].sCmd);
							
						}
						else 
						{
							gEngfuncs.pfnClientCmd(g_MGUI_MAX[i].sCmd);
							// Close MGUI
							g_mgui_candraw = 0;
						}
					}
				}
				// 正常按钮
				int iCenter = g_MGUI_MAX[i].Width - g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft - g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iRight;
				int iStartX = g_MGUI_MAX[i].Xpos;
				MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[0],iStartX,g_MGUI_MAX[i].Ypos,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
				iStartX += g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iLeft;
				MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[1],iStartX,g_MGUI_MAX[i].Ypos,iCenter,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
				iStartX += iCenter;
				MH_DrawTGAFunction2(g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iImage[2],iStartX,g_MGUI_MAX[i].Ypos,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iRight,g_MGUI_TypeDef[g_MGUI_MAX[i].iDefine].iHeight);
			}
		}

		if(iStore) // change pos
		{
			g_MGUI_MAX[i].Xpos = iStoreX;
			g_MGUI_MAX[i].Ypos = iStoreY;
		}
	}
	iOldButton = g_mgui_mouseevent;
	MH_DrawTGAFunction2(1,iMouseX,iMouseY,5,5);
	if(!iExtraButtonActive) g_mgui_file_extra_drawing = 0;
	return;
}
int MGUI_FindDefine(char *pName)
{
	for(int i=1;i<=g_mgui_def_count;i++)
	{
		if(!strcmp(pName,g_MGUI_TypeDef[g_mgui_def_count].Name))
		{
			return i;
		}
	}
	return 0;		
}
int MGUI_ReadTypeDefClass(char *Name)
{
	char szName[128];
	sprintf(szName,"%s",Name);
	LogToFile("MGUI加载定义文件:: 准备加载%s",szName);
	FILE *pFile = fopen(szName,"rt");
	if(!pFile) 
	{
		LogToFile("加载MGUI定义文件:%s失败！",szName);
		return 0;
	}
	g_mgui_def_count ++;

	static char szBuff[512];
	szBuff[0] = '\0';
	char szTemp[9][8];
	int iCount2=0;
	for(int i=0 ; i<3;i++)
	{
		for(int j=0;j<3;j++)
		{
			sprintf(szTemp[iCount2],"%d_%d",i,j);
			iCount2 ++;
		}
		
	}
	while(!feof(pFile))
	{
		fgets(szBuff,sizeof(szBuff)-1,pFile);
		if(szBuff[strlen(szBuff)-1] =='\n') szBuff[strlen(szBuff)-1] = '\0'; // Line end
		if(szBuff[0] =='/' && szBuff[1] =='/') continue;  //  -- //
		
		
		// 读取配置项
		if(szBuff[0] == '[')
		{
			sprintf(g_MGUI_TypeDef[g_mgui_def_count].Name,"%s",Q_FindCenterString(szBuff,'[',']'));
			LogToFile("加载配置项 %s",g_MGUI_TypeDef[g_mgui_def_count].Name);
			continue;
		}
		if(szBuff[0] == 'T' && szBuff[2] == 'C')
		{
			g_MGUI_TypeDef[g_mgui_def_count].iClass= atoi(Q_GetCharLeft(szBuff,'='));
		}
		char szTemp2[8];
		sprintf(szTemp2,"%c_%c",szBuff[0],szBuff[2]);
		for(int i=0;i<9;i++)
		{
			if(!strcmp(szTemp[i],szTemp2))
			{
				
				g_MGUI_TypeDef[g_mgui_def_count].iImage[i] = DrawTgaGetID(Q_GetCharLeft(szBuff,'='));
				if(i == 0)
				{
					g_MGUI_TypeDef[g_mgui_def_count].iLeft = g_MHTga[g_MGUI_TypeDef[g_mgui_def_count].iImage[i]].width;
				}
				else if(i==2)
				{
					g_MGUI_TypeDef[g_mgui_def_count].iRight = g_MHTga[g_MGUI_TypeDef[g_mgui_def_count].iImage[i]].width;
					g_MGUI_TypeDef[g_mgui_def_count].iHeight = g_MHTga[g_MGUI_TypeDef[g_mgui_def_count].iImage[i]].height;
				}
				break; 
			}
		}
	}
	return 1;

}
int MGUI_ReadFromResourceFile(char *Name)
{
	// 检测是否重复
	char szName[128];
	sprintf(szName,"%s",Name);
	LogToFile("MGUI加载资源文件:: 准备加载%s",szName);

	int iCheck = 0;
	int iEditing = 0;
	for(int i=1;i<=g_mgui_file_count;i++)
	{
		if(!strcmp(Name,g_mgui_file[i]))
		{
			iCheck = i;
			iEditing = i;
			MGUI_ReSortElements(i);
		}
	}
	
	FILE *pFile = fopen(szName,"rt");
	if(!pFile) 
	{
		LogToFile("加载MGUI文件:%s失败！",szName);
		return 0;
	}
	if(!iCheck) 
	{
		g_mgui_file_count ++;
		iEditing = g_mgui_file_count;
	}
	sprintf(g_mgui_file[iEditing],"%s",Name);
	// 开始读取
	static char szBuff[512];
	szBuff[0] = '\0';
	int iReadSection = 0;
	g_MGUI_File[iEditing].iStartID = g_mgui_count +1;
	while(!feof(pFile))
	{
		fgets(szBuff,sizeof(szBuff)-1,pFile);
		if(szBuff[strlen(szBuff)-1] =='\n') szBuff[strlen(szBuff)-1] = '\0'; // Line end
		if(szBuff[0] =='/' && szBuff[1] =='/') continue;  //  -- //
		
		// 读取配置项
		if(szBuff[0] == '[')
		{
			g_mgui_count ++;
			iReadSection = 1;
			sprintf(g_MGUI_MAX[g_mgui_count].sName,"%s",Q_FindCenterString(szBuff,'[',']'));
			g_MGUI_MAX[g_mgui_count].iFileID = iEditing;
			continue;
		}
		if(szBuff[0] == 'X')
		{
			g_MGUI_MAX[g_mgui_count].Xpos = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'Y')
		{
			g_MGUI_MAX[g_mgui_count].Ypos = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'W')
		{
			g_MGUI_MAX[g_mgui_count].Width = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'H')
		{
			g_MGUI_MAX[g_mgui_count].Height = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'S')
		{
			g_MGUI_MAX[g_mgui_count].iSize = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'C' && szBuff[1] == 'l')
		{
			char *p = Q_GetCharLeft(szBuff,'=');
			if(p[0] == 'I') // image
			{
				g_MGUI_MAX[g_mgui_count].iClass = CLASS_IMAGE;
			}
			else if(p[0] == 'B') // button
			{
				g_MGUI_MAX[g_mgui_count].iClass = CLASS_BUTTON;
			}
			else if(p[0] == 'L' && p[1] == 'A') // button
			{
				g_MGUI_MAX[g_mgui_count].iClass = CLASS_LABEL;
			}
			else if(p[0] == 'E') // button
			{
				g_MGUI_MAX[g_mgui_count].iClass = CLASS_EXTRA_BUTTON;
			}
			else if(p[0] == 'D') // button
			{
				g_MGUI_MAX[g_mgui_count].iClass = CLASS_DEFINE;
			}
			else if(p[0] == 'C') // button
			{
				g_MGUI_MAX[g_mgui_count].iClass = CLASS_CHECKBOX;
			}
			else if(p[0] == 'L' && p[1] == 'I') // button
			{
				g_MGUI_MAX[g_mgui_count].iClass = CLASS_LINE;
			}
		}
		else if(szBuff[0] == 'P' &&  (g_MGUI_MAX[g_mgui_count].iClass == CLASS_IMAGE || g_MGUI_MAX[g_mgui_count].iClass == CLASS_BUTTON || g_MGUI_MAX[g_mgui_count].iClass == CLASS_EXTRA_BUTTON))
		{
			char *p = Q_GetCharLeft(szBuff,'=');
			g_MGUI_MAX[g_mgui_count].iTexID = DrawTgaGetID(p);
		}
		else if(szBuff[0] == 'L' && (g_MGUI_MAX[g_mgui_count].iClass == CLASS_LABEL || g_MGUI_MAX[g_mgui_count].iClass == CLASS_BUTTON || g_MGUI_MAX[g_mgui_count].iClass == CLASS_EXTRA_BUTTON))
		{
			char *p = Q_GetCharLeft(szBuff,'=');
			sprintf(g_MGUI_MAX[g_mgui_count].sPic,"%s",p);
		}
		else if(szBuff[0] == 'A')
		{
			g_MGUI_MAX[g_mgui_count].iAutoResize = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'C'&& szBuff[1] == 'o') // cmd
		{
			char *p = Q_GetCharLeft(szBuff,'=');
			sprintf(g_MGUI_MAX[g_mgui_count].sCmd,"%s",p);
		}
		else if(szBuff[0] == 'M') //mgui
		{
			char *p = Q_GetCharLeft(szBuff,'=');
			sprintf(g_MGUI_MAX[g_mgui_count].sMGUI,"%s",p);
		}
		else if(szBuff[0] == 'F')
		{
			g_MGUI_MAX[g_mgui_count].iFollowMouse = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'C' && szBuff[1] == 'R')
		{
			g_MGUI_MAX[g_mgui_count].r = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'C' && szBuff[1] == 'G')
		{
			g_MGUI_MAX[g_mgui_count].g = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'C' && szBuff[1] == 'B')
		{
			g_MGUI_MAX[g_mgui_count].b = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'C' && szBuff[1] == 'A')
		{
			g_MGUI_MAX[g_mgui_count].a = atoi(Q_GetCharLeft(szBuff,'='));
		}
		else if(szBuff[0] == 'D')
		{
			g_MGUI_MAX[g_mgui_count].iDefine = MGUI_FindDefine(Q_GetCharLeft(szBuff,'='));
		}
	}
	fclose(pFile);
	g_MGUI_File[iEditing].iEndID = g_mgui_count;
	LogToFile("成功加载MGUI文件:%s 文件ID:%d 当前元素数目:%d[元素信息%d/%d]",Name,iEditing,g_mgui_count,g_MGUI_File[iEditing].iStartID,g_MGUI_File[iEditing].iEndID);
	g_mgui_candraw = 1;
	return iEditing;
}
char *Q_GetCharLeft(char *p,char sym)
{
	static char szString[128];
	memset(szString,0,sizeof(szString));
	int iStringPos = 0;
	int iBeginWrite = 0;

	for(p;;p++)
	{
		if(p[0] && p[0] == sym) 
		{
			iBeginWrite = 1;
			continue;
		}
		if(!p[0] || p[0] == '\0')
		{
			return szString;
		}
		if(iBeginWrite)
		{
			szString[iStringPos] = p[0];
			iStringPos ++;
		}
	}

}
char *Q_FindCenterString(char *p,char left,char right)
{
	static char szString[128];
	int iBeginWrite = 0;
	int iStringPos = 0;
	memset(szString,0,sizeof(szString));

	for(p;;p++)
	{
		if(p[0] && p[0] == left) 
		{
			iBeginWrite = 1;
			continue;
		}
		if(!p[0] || p[0] == right || p[0] == '\0')
		{
			break;
		}
		if(iBeginWrite)
		{
			szString[iStringPos] = p[0];
			iStringPos ++;
		}
	}
	szString[iStringPos] = '\0';
	return szString;
}