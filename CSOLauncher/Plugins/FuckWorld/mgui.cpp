#include "base.h"
#include "imm.h"
#include "BaseUI.h"


MGUI_Panel *pRootPanel = NULL;
MGUI_Image *pImage;
HWND g_hWnd;
WNDPROC g_OldProc;

int g_mgui_keynum=-1;
int g_mgui_mouseevent,g_mgui_oldmouseevent,g_mgui_candraw;
int g_mgui_tga_imebg;

int g_mouse_w, g_mouse_h;
//int g_mgui_tga_button[3];
float g_mgui_nextclicktime;
int g_mgui_mouse;
CANDIDATELIST *CandidateList;
bool g_bDrawIme = false;
int iCanSetMouse = 0;

void MGUI_Base::Paint(MGUI_Base *pParent)
{
	return;
}
////////////////////// PANEL

MGUI_Panel::MGUI_Panel(void)
{
	iClass = MGUI_PANEL;
	m_iClosing = 0;
	memcpy(m_iTexture,g_UI_Panel,sizeof(g_UI_Panel));
	m_iTitleHeight = 0;
	pNext = NULL;
	m_bHasClose = false;
	m_iTitleSize = 0;
	memset(m_pTitle,0,sizeof(m_pTitle));
	return;
}
MGUI_Panel::~MGUI_Panel(void)
{
	return;
}
int MGUI_Panel::SetTexture(int iTex[3][3])
{
	memcpy(m_iTexture,iTex,sizeof(iTex));
	//DrawTgaGetID(pName);
	return 1;
}
MGUI_Panel *MGUI_CreatePanel(int x,int y,int w,int h,int iTitleHeight,bool CanMove)
{
	MGUI_Panel *pPanel = new MGUI_Panel;
	if(!pPanel)
	{
		return NULL;
	}
	pPanel->x = x;
	pPanel->prevx = x;
	pPanel->prevy = y;
	pPanel->y = y;
	pPanel->w = w;
	pPanel->h = h;
	pPanel->m_bCanMove = CanMove;
	pPanel->m_iTitleHeight = iTitleHeight;
	pPanel->pNextPanel = 0x0;
	pPanel->m_iHaveBg = 1;
	memcpy(pPanel->m_iTexture,g_UI_Panel_Dark,sizeof(g_UI_Panel_Dark));
	
	if(!pRootPanel)
	{
		pRootPanel = pPanel;
	}
	else
	{
		MGUI_Panel *pPanelNext = pRootPanel;
		while(pPanelNext->pNextPanel)
		{
			pPanelNext = pPanelNext->pNextPanel;
		}
		pPanelNext->pNextPanel = pPanel;
	}
	return pPanel;
}
bool MGUI_Panel::IsInRect(void)
{
	int iMouseX,iMouseY;
	gEngfuncs.GetMousePosition( &iMouseX,&iMouseY);
	if( iMouseX>x && iMouseX< x+w && iMouseY>y && iMouseY<y+m_iTitleHeight) return true;
	return false;
}
bool MGUI_Panel::InsertControl(MGUI_Base *pChild)
{
	MGUI_Base *pTemp = (MGUI_Base *)this;
	while(pTemp->pNext)
	{
		pTemp = pTemp->pNext;
	}
	pTemp->pNext = pChild;
	return true;
}
char *MGUI_Panel::GetTextEntryText(int iClass)
{
	MGUI_Base *pNext = this;
	while(pNext)
	{
		if(pNext->iClass == MGUI_TEXTENTRY)
		{
			MGUI_TextEntry *pEntry = (MGUI_TextEntry *)pNext;
			if(pEntry->m_iClass == iClass)
			{
				return pEntry->m_pText;
			}
		}
		pNext = pNext->pNext;
	}
	return NULL;
}
////////////////////// IMAGE
void MGUI_Image::SetTexture(char *pName)
{
	//m_iTexture = g_pSurface->CreateNewTextureID();
	m_iTexture = FindTexture(pName);

	//return m_iTexture;
}
void MGUI_Image::SetVisible(bool bVisible)
{
	m_bVisible = bVisible;
}

MGUI_Image *MGUI_CreateImage(MGUI_Base *pParent,int x,int y,int w,int h,bool AutoResize,bool ForceSize)
{
	MGUI_Image *pImage = new MGUI_Image;
	if(!pImage)
	{
		return NULL;
	}
	pImage->x = x;
	pImage->y = y;
	pImage->w = w;
	pImage->h = h;
	pImage->m_bAutoResize = AutoResize;
	pImage->m_bForceSize = ForceSize;
	pImage->pParent = pParent;
	pImage->pNext = NULL;
	pImage->iClass = MGUI_IMAGE;
	pImage->m_bVisible = true;
	pImage->m_iTex_Type = MGUI_TEX_TYPE_1;
	//pImage->m_iTexture = 0;
	//pImage->m_iTexture = g_pSurface->CreateNewTextureID();
	((MGUI_Panel *)pParent)->InsertControl(pImage);
	return pImage;
}
void MGUI_Image::Paint(MGUI_Base *pBaseParent)
{
	if(!pParent) return;
	if(pParent == pBaseParent)
	{
		if(((MGUI_Panel *)pBaseParent)->m_iClosing || !m_bVisible || m_iTexture == -1) return;
		if(m_iTex_Type == MGUI_TEX_TYPE_1)
			MH_DrawTGAFunction2(g_Texture[m_iTexture].iTexture,x+pParent->x,pParent->y+y,w,h,255);
		if(m_iTex_Type == MGUI_TEX_TYPE_3)
			MH_DrawTGA_3(m_iTexture3,x+pParent->x,pParent->y+y,w,h,255);
		if(m_iTex_Type == MGUI_TEX_TYPE_9)
			MH_DrawTGA_9(m_iTexture9,x+pParent->x,pParent->y+y,w,h,255);
	}
}
/////////// TEXTENTRY
void MGUI_TextEntry::Paint(MGUI_Base *pBaseParent)
{
	if(!pParent) return;
	if(pParent == pBaseParent)
	{
		if(((MGUI_Panel *)pBaseParent)->m_iClosing) return;
		// Draw Bg
		//MH_DrawTGAFunction2(g_mgui_tga_imebg,x+pParent->x,pParent->y+y,w,48,255);
		// Draw Text
		Fonts_SetSize(20,20);
		Fonts_SetColor(0,0,0,255);
		wchar_t pWchar[255];
		Fonts_C2W(pWchar,255,m_pText);
		int iEnd=Fonts_Draw(pWchar,x+pParent->x+10,pParent->y+y+26,w,100);
		// Draw Line
		if(m_bHasFocus)
		{
			// Draw IME
			if(CandidateList)
			{
				if( g_bDrawIme) 
				{
					Fonts_SetSize(20,20);
					if(CandidateList->dwCount>1)
					{
						int iLong = 0;
						for(int i=0; i < CandidateList->dwCount;i++)
						{
							char *pText = (char*)CandidateList + CandidateList->dwOffset[ i ] ;
							if(pText)
							{
								int iTemp = strlen(pText);
								if(iTemp>iLong) iLong = iTemp; 

							}
						}
						// Draw INSIDE
						Fonts_SetColor(255,0,0,255);
						gEngfuncs.pfnFillRGBA(iEnd,pParent->y+y+26-20,iLong *10 + 20,24,135,135,135,255);
						iEnd = Fonts_Draw(ANSIToUnicode((char*)CandidateList + CandidateList->dwOffset[0]),iEnd,pParent->y+y+26,1000,100);
						// Draw LIST
						int iTotal = CandidateList->dwCount;
						gEngfuncs.pfnFillRGBA(iEnd-10,pParent->y+y - 24*CandidateList->dwCount,iLong*10+40,24*CandidateList->dwCount,40,40,40,255);

						// GetLongest
						for(int i=0; i < CandidateList->dwCount;i++)
						{ 
							char *pText = (char*)CandidateList + CandidateList->dwOffset[ i ] ;
							if(pText)
							{
								Fonts_SetColor(255,255,255,255);
								char Content[256];
								sprintf(Content,"%d.%s",i+1,pText);
								Fonts_Draw(ANSIToUnicode(Content),iEnd,pParent->y+y - (iTotal-i)*24 +2+18,1000,100);
							}
						}
					}
				}
			}
			float fDelta = g_flTime;
			fDelta-=(int)fDelta;
			if(fDelta > 0.5)
			{
				Fonts_Draw(L"|",iEnd,pParent->y+y+26,w,100);
			}

		}
	}
	return;
}
bool MGUI_TextEntry::IsInRect(void)
{
	int iMouseX,iMouseY;
	gEngfuncs.GetMousePosition( &iMouseX,&iMouseY);
	int iX = pParent->x+x;
	int iY = pParent->y+y;
	if( iMouseX>iX && iMouseX< iX+w && iMouseY>iY && iMouseY<iY+48) return true;
	return false;
}
MGUI_TextEntry *MGUI_CreateTextEntry(MGUI_Base *pParent,int x,int y,int w)
{
	MGUI_TextEntry *pTextEntry = new MGUI_TextEntry;
	if(!pTextEntry)
	{
		return NULL;
	}
	pTextEntry->x = x;
	pTextEntry->y = y;
	pTextEntry->w = w;
	pTextEntry->pParent = pParent;
	pTextEntry->m_bHasFocus = false;
	pTextEntry->pNext = NULL;
	pTextEntry->iClass = MGUI_TEXTENTRY;
	pTextEntry->m_iClass = 0;
	pTextEntry->SetText("");
	((MGUI_Panel *)pParent)->InsertControl(pTextEntry);
	return pTextEntry;
}
void MGUI_TextEntry::SetText(char *pszText)
{
	sprintf(m_pText,"%s",pszText);
}
////////// MENU
MGUI_Menu *MGUI_CreateMGUI_Menu(MGUI_Base *pParent,int x,int y,int w)
{
	MGUI_Menu *pMenu = new MGUI_Menu;
	if(!pMenu)
	{
		return NULL;
	}
	pMenu->x = x;
	pMenu->y = y;
	pMenu->w = w;
	pMenu->pParent = pParent;
	pMenu->pNext = NULL;
	pMenu->iClass = MGUI_MENU;
	pMenu->m_iNum = 0;
	pMenu->m_bShow = true;
	pMenu->m_iOnFocus = 0;
	((MGUI_Panel *)pParent)->InsertControl(pMenu);
	return pMenu;
}
void MGUI_Menu::AddItem(char *pItemName)
{
	m_iNum ++;
	sprintf(pText[m_iNum],"%s",pItemName);
	return;
}
void MGUI_Menu::Paint(MGUI_Base *pBaseParent)
{
	if(!pParent||!m_bShow) return;
	if(pParent == pBaseParent)
	{
		if(((MGUI_Panel *)pBaseParent)->m_iClosing) return;
		
		// Draw Bg
		int iTotal = m_iNum;
		gEngfuncs.pfnFillRGBA(pParent->x+x,pParent->y+y,w,24*iTotal,255,255,0,100);
		// Draw Border
		// Up
		gEngfuncs.pfnFillRGBA(pParent->x+x,pParent->y+y-1,w,1,255,255,255,255);
		// Down
		gEngfuncs.pfnFillRGBA(pParent->x+x,pParent->y+y+24*iTotal,w,1,255,255,255,255);
		// Left
		gEngfuncs.pfnFillRGBA(pParent->x+x-1,pParent->y+y,1,24*iTotal,255,255,255,255);
		// Right
		gEngfuncs.pfnFillRGBA(pParent->x+x+w,pParent->y+y,1,24*iTotal,255,255,255,255);
		// Draw Text
		for(int i=1;i<=m_iNum;i++)
		{
			if(m_iOnFocus == i)
			{
				gEngfuncs.pfnFillRGBA(pParent->x+x,pParent->y+y+24*(i-1),w,24,255,255,0,200);
			}
			Fonts_SetSize(16,16);
			int iStartX = w - Fonts_GetLen(ANSIToUnicode(pText[i]));
			iStartX/=2;
			Fonts_SetColor(255,0,0,255);
			Fonts_Draw(ANSIToUnicode(pText[i]),pParent->x+x+iStartX,pParent->y+y+24*i-6,100,100);
			gEngfuncs.pfnFillRGBA(pParent->x+x,pParent->y+y+24*i,w,1,255,255,255,255);
		}
	}
}
int MGUI_Menu::IsInRect(void)
{
	int iMouseX,iMouseY;
	gEngfuncs.GetMousePosition( &iMouseX,&iMouseY);
	int iX = pParent->x+x;
	int iY = pParent->y+y;
	for(int i=1;i<=m_iNum;i++)
	{
		if( iMouseX>iX && iMouseX< iX+w && iMouseY>iY && iMouseY<iY+24*i) 
		{
			m_iOnFocus = i;
			return i;
		}
	}
	m_iOnFocus = 0;
	return 0;
}
////// BUTTON
MGUI_Button *MGUI_CreateButton(MGUI_Base *pParent,int x,int y,int w,int h)
{
	MGUI_Button *pButton = new MGUI_Button;
	if(!pButton)
	{
		return NULL;
	}
	pButton->x = x;
	pButton->y = y;
	pButton->w = w;
	pButton->h = h;
	pButton->pParent = pParent;
	memset(pButton->pszLabel,0,sizeof(pButton->pszLabel));
	memset(pButton->pszCommand,0,sizeof(pButton->pszCommand));
	memset(pButton->pszCommand2,0,sizeof(pButton->pszCommand2));
	memset(pButton->iTga,0,sizeof(pButton->iTga));
	memset(pButton->iTga3,0,sizeof(pButton->iTga));
	memset(pButton->iTga9,0,sizeof(pButton->iTga));
	/*pButton->iTga[0] = g_pSurface->CreateNewTextureID();
	pButton->iTga[1] = g_pSurface->CreateNewTextureID();
	pButton->iTga[2] = g_pSurface->CreateNewTextureID();*/

	pButton->m_iType = MGUI_BUTTON_TYPE_COMMAND;
	pButton->m_iType2 = MGUI_BUTTON_TYPE_COMMAND;
	pButton->pNext = NULL;
	pButton->iClass = MGUI_BUTTON;
	pButton->m_iStat = 0;
	pButton->m_fNextClick = 0;
	pButton->m_Tex_Type = MGUI_TEX_TYPE_1;
	pButton->m_iOffset[0] = pButton->m_iOffset[1] = 0;
	
	/*pButton->iTga[0] = g_mgui_tga_button[0];
	pButton->iTga[1] = g_mgui_tga_button[1];
	pButton->iTga[2] = g_mgui_tga_button[2];*/
	/*memcpy(pButton->iTga3[0],g_UI_Button[0],sizeof(g_UI_Button[0]));
	memcpy(pButton->iTga3[1],g_UI_Button[1],sizeof(g_UI_Button[1]));
	memcpy(pButton->iTga3[2],g_UI_Button[2],sizeof(g_UI_Button[2]));*/
	pButton->m_iColor32[0] = pButton->m_iColor32[1] = pButton->m_iColor32[2]= pButton->m_iColor32[3] = 255;
	pButton->m_bVisible = true;
	pButton->m_bEnabled = true;
	pButton->m_bEnabled2 = true;
	pButton->m_iSize = h-16;
	pButton->m_OverPanel = 0x0;
	pButton->m_iKey = -1;
	
	((MGUI_Panel *)pParent)->InsertControl(pButton);
	return pButton;  
}
void MGUI_Button::Paint(MGUI_Base *pBaseParent)
{
	if(!pParent || !m_bVisible) return;
	if(pParent == pBaseParent)
	{		
		if(((MGUI_Panel *)pBaseParent)->m_iClosing) return;		

		if(iTga[m_iStat]!=-1 && m_bEnabled)
		{
			if(m_Tex_Type == MGUI_TEX_TYPE_1)
				MH_DrawTGAFunction2(g_Texture[iTga[m_iStat]].iTexture,x+pParent->x,pParent->y+y,w,h,255);
			else if(m_Tex_Type == MGUI_TEX_TYPE_3)
				MH_DrawTGA_3(iTga3[m_iStat],x+pParent->x,pParent->y+y,w,h,255);
			else
				MH_DrawTGA_9(iTga9[m_iStat],x+pParent->x,pParent->y+y,w,h,255);
		}
		else
		{
			if(m_Tex_Type == MGUI_TEX_TYPE_1)
				MH_DrawTGAFunction2(g_Texture[iTga[0]].iTexture,x+pParent->x,pParent->y+y,w,h,255);
			else if(m_Tex_Type == MGUI_TEX_TYPE_3)
				MH_DrawTGA_3(iTga3[0],x+pParent->x,pParent->y+y,w,h,255);
			else
				MH_DrawTGA_9(iTga9[0],x+pParent->x,pParent->y+y,w,h,255);	
		}
		// Draw Label
		if(pszLabel[0])
		{
			//int iOffset = w /2 - wcslen(pszLabel) * (m_iSize)/2;
			Fonts_SetSize(m_iSize,m_iSize);
			int iOffset = w /2 - Fonts_GetLen(pszLabel) / 2;
			
			if(m_bEnabled)
				Fonts_SetColor(m_iColor32[0],m_iColor32[1],m_iColor32[2],m_iColor32[3]);
			else
				Fonts_SetColor(75,75,75,200);
			Fonts_Draw(pszLabel,x+pParent->x+iOffset+m_iOffset[0],pParent->y+y + h/2+m_iSize/2-1+m_iOffset[1],1000,1000);
		}

	}
}
void MGUI_Button::SetImage(char *n, char *o, char *c)
{	
	iTga[0] = FindTexture(n);
	iTga[1] = FindTexture(o);
	iTga[2] = FindTexture(c);
	//g_pSurface->DrawSetTextureFile(iTga[0],n,true,true);
	//g_pSurface->DrawSetTextureFile(iTga[1],o,true,true);
	//g_pSurface->DrawSetTextureFile(iTga[2],c,true,true);
}
void MGUI_Button::SetImage3(int iTex[3][3])
{
	memcpy(iTga3,iTex,sizeof(iTex));
}
void MGUI_Button::SetVisible(bool bVisible)
{
	m_bVisible = bVisible;
}
void MGUI_Button::SetEnabled(bool fEnabled)
{
	m_bEnabled = fEnabled;
}
void MGUI_Button::SetType(int iType)
{
	m_iType = iType;
}
void MGUI_Button::SetCommand(char *pCommand)
{
	sprintf(pszCommand,"%s",pCommand);
}
void MGUI_Button::SetCommand2(char *pCommand)
{
	sprintf(pszCommand2,"%s",pCommand);
}
void MGUI_Button::SetColor(int r,int g,int b,int a)
{
	m_iColor32[0] = r;
	m_iColor32[1] = g;
	m_iColor32[2] = b;
	m_iColor32[3] = a;
}
void MGUI_Button::SetKey(int iKey)
{
	m_iKey = iKey;
}
bool MGUI_Button::IsInRect(void)
{
	/*if (!m_bEnabled)
	{
		if(m_OverPanel) m_OverPanel->m_iClosing = 1;
		return false;
	}*/
	int iMouseX,iMouseY;
	gEngfuncs.GetMousePosition( &iMouseX,&iMouseY);
	int iX = pParent->x+x;
	int iY = pParent->y+y;
	if( iMouseX>=iX && iMouseX<= iX+w && iMouseY>=iY && iMouseY<=iY+h) 
	{
		if(m_OverPanel)
		{
			m_OverPanel->m_iClosing = 0;
		}
		return true;
	}
	if(m_OverPanel) m_OverPanel->m_iClosing = 1;
	return false;
}
void MGUI_Send_Cmd(char *szCmd)
{
	if(strstr(szCmd,"MGUI."))
	{
		if(strstr(szCmd,"BuyMenu_SaveFav"))
		{				
			char num[3];
			num[2] = '\0';
			strncpy(num, szCmd + strlen("MGUI.BuyMenu_SaveFav"), 2);
			BTEPanel_BuyMenu_SetFav(atoi(num));
		}
		if(strstr(szCmd,"ShowBuyMenu"))
		{
			BTEPanel_BuyMenu_UpdateItems(-1,"");
			BTEPanel_BuyMenu_SetPage(0,0);
		}
		if(strstr(szCmd,"SaveTeamSuit"))
		{
			BTEPanel_TeamSuit_Save();
		}
		if(strstr(szCmd,"TeamSuitPrevSlot"))
		{
			BTEPanel_TeamSuit_SetSlot(-1);
		}
		if(strstr(szCmd,"TeamSuitNextSlot"))
		{
			BTEPanel_TeamSuit_SetSlot(1);
		}	

	}
	else
		gEngfuncs.pfnClientCmd(szCmd);

}
void MGUI_Button::Click(void)
{
	if(!m_bVisible || !m_bEnabled) return;
	g_mgui_keynum = -1;
	g_Next_Key_CanUse = g_flTime + 0.15;
	if(m_iType == MGUI_BUTTON_TYPE_CHANGE_NAME)
	{
		char *name = ((MGUI_Panel *)pParent)->GetTextEntryText(1);
		if(name) 
		{
			char szCmd[64];
			sprintf(szCmd,"name %s",UnicodeToUTF8(ANSIToUnicode(name)));
			MGUI_Send_Cmd(szCmd);
		}
	}
	else if(m_iType == MGUI_BUTTON_TYPE_COMMAND_CLOSEPANEL)
	{
		MGUI_Send_Cmd(pszCommand);
		((MGUI_Panel *)pParent)->m_iClosing = 1;
	}
	else if(m_iType == MGUI_BUTTON_TYPE_CLOSEALL)
	{
		MGUI_Send_Cmd(pszCommand);
		((MGUI_Panel *)pParent)->m_iClosing = 1;
		g_mgui_candraw = 0;		
	}
	else
	{
		MGUI_Send_Cmd(pszCommand);
	}
}
void MGUI_Button::Click2(void)
{
	if(!m_bVisible || !m_bEnabled2) return;
	g_mgui_keynum = -1;
	g_Next_Key_CanUse = g_flTime + 0.15;
	if(m_iType2 == MGUI_BUTTON_TYPE_COMMAND_CLOSEPANEL)
	{
		MGUI_Send_Cmd(pszCommand2);
		((MGUI_Panel *)pParent)->m_iClosing = 1;
		g_Next_Key_CanUse = g_flTime + 0.1;
	}
	else if(m_iType2 == MGUI_BUTTON_TYPE_CLOSEALL)
	{
		MGUI_Send_Cmd(pszCommand2);
		((MGUI_Panel *)pParent)->m_iClosing = 1;
		g_mgui_candraw = 0;
		g_Next_Key_CanUse = g_flTime + 0.1;
	}
	else
	{
		MGUI_Send_Cmd(pszCommand2);
	}
}
void MGUI_Button::SetLabel(wchar_t *pLabel)
{
	wcscpy(pszLabel,pLabel);
	Fonts_LoadString(pLabel);
}
////////////// Label
MGUI_Label *MGUI_CreateLabel(MGUI_Base *pParent,int x,int y,int w,int h)
{
	MGUI_Label *pLabel = new MGUI_Label;
	if(!pLabel)
	{
		return NULL;
	}
	pLabel->x = x;
	pLabel->y = y;
	pLabel->w = w;
	pLabel->h = h;
	pLabel->m_iSize = 12;
	pLabel->pNext = NULL;
	pLabel->m_bVisible = true;
	pLabel->m_iColor32[0] = pLabel->m_iColor32[1] = pLabel->m_iColor32[2]= pLabel->m_iColor32[3] = 255;
	pLabel->pParent = pParent;
	memset(pLabel->pszLabel,0,sizeof(pLabel->pszLabel));
	pLabel->iClass = MGUI_LABEL;
	pLabel->m_iAlignment = MGUI_Left;
	((MGUI_Panel *)pParent)->InsertControl(pLabel);
	return pLabel;
}
void MGUI_Label::SetSize(int size)
{
	m_iSize = size;
}
void MGUI_Label::SetVisible(bool bVisible)
{
	m_bVisible = bVisible;
}
void MGUI_Label::Paint(MGUI_Base *pBaseParent)
{
	if(!pParent || !m_bVisible) return;
	if(pParent == pBaseParent)
	{
		if(((MGUI_Panel *)pBaseParent)->m_iClosing) return;
		// Draw Label
		if(pszLabel[0])
		{
			Fonts_SetSize(m_iSize,m_iSize);
			Fonts_SetColor(m_iColor32[0],m_iColor32[1],m_iColor32[2],m_iColor32[3]);
			if(m_iAlignment == MGUI_Left)
				Fonts_Draw2(pszLabel,x+pParent->x,pParent->y+y + m_iSize / 2 + h / 2,w,h,3);
			if(m_iAlignment == MGUI_Center)
				Fonts_Draw2(pszLabel,x+pParent->x+w/2-Fonts_GetLen(pszLabel)/2,pParent->y+y + m_iSize /2 + h / 2,w,h,3);
			if(m_iAlignment == MGUI_Right)
				Fonts_Draw2(pszLabel,x+pParent->x+w-Fonts_GetLen(pszLabel),pParent->y+y + m_iSize /2 + h / 2,w,h,3);
				
		}

	}
}
void MGUI_Label::SetColor(int r,int g,int b,int a)
{
	m_iColor32[0] = r;
	m_iColor32[1] = g;
	m_iColor32[2] = b;
	m_iColor32[3] = a;
}
void MGUI_Label::SetLabel(wchar_t *pLabel)
{
	wcscpy(pszLabel,pLabel);
	Fonts_LoadString(pLabel);
}
/////////
LRESULT CALLBACK g_NewProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if(!g_mgui_candraw) return CallWindowProc(g_OldProc, hWnd, message, wParam, lParam);

	switch (message)
	{
		case WM_CHAR:
		{
			char *pText = MGUI_FindFocusTextEntryText();
			if (pText)
			{
				if (wParam == VK_BACK)
				{
					int len = strlen(pText);

					if (pText[len - 1] < 0)
						pText[len - 2] = '\0';
					else
						pText[len - 1] = '\0';
				}
				else if(wParam != VK_RETURN)
				{
					int len = strlen(pText);
					pText[len] = wParam;
					pText[len + 1] = '\0';
				}
				else
				{
					MGUI_SetFocusTextEntryDisabled();
				}

				return 1;
			}

			break;
		}

		case WM_IME_CHAR:
		{
			char *pText = MGUI_FindFocusTextEntryText();
			if (pText)
			{
				char buf[3];
				buf[0] = wParam >> 8;
				buf[1] = (byte)wParam;
				buf[2] = '\0';
				strcat(pText, buf);
				return 1;
			}

			break;
		}
		case WM_IME_NOTIFY:
		{
			HIMC hImc = ImmGetContext(hWnd);
			if(!hImc) break;
			if(wParam == IMN_CHANGECANDIDATE)
			{
				DWORD dwSize;
				dwSize = ImmGetCandidateList(hImc,0,NULL,0);
				if(dwSize > 0)
				{
					CandidateList = (LPCANDIDATELIST)GlobalAlloc( GPTR, dwSize );
					g_bDrawIme = true;
					ImmGetCandidateList(hImc,0,CandidateList,dwSize);
				}
				else memset(CandidateList,0,sizeof(CandidateList));
			}
			else if(wParam == IMN_CLOSECANDIDATE)
			{
				g_bDrawIme = false;
			}
			ImmReleaseContext( hWnd, hImc );
		}
	}
	return CallWindowProc(g_OldProc, hWnd, message, wParam, lParam);

}
char *MGUI_FindFocusTextEntryText(void)
{
	MGUI_Base *pNextControl = pRootPanel;
	while(pNextControl->pNext)
	{
		if(pNextControl->pNext->iClass == MGUI_TEXTENTRY)
		{
			if(  ((MGUI_TextEntry*)pNextControl->pNext)->m_bHasFocus )
			{
				return ((MGUI_TextEntry*)pNextControl->pNext)->m_pText;
			}
		}
		pNextControl = pNextControl->pNext;
	}
	return NULL;
}
void MGUI_SetFocusTextEntryDisabled(void)
{
	MGUI_Base *pNextControl = pRootPanel;
	while(pNextControl->pNext)
	{
		if(pNextControl->pNext->iClass == MGUI_TEXTENTRY)
		{
			if(  ((MGUI_TextEntry*)pNextControl->pNext)->m_bHasFocus )
			{
				((MGUI_TextEntry*)pNextControl->pNext)->m_bHasFocus = false;
			}
		}
		pNextControl = pNextControl->pNext;
	}
	return;
}
void MGUI_Init()
{
	// RESOURCE INIT
	//g_mgui_tga_imebg = DrawTgaGetID("other\\ui\\panel\\imebg");	
	//g_mgui_mouse =  DrawTgaGetID("other\\ui\\panel\\mouse");
	/*g_mgui_tga_imebg = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_mgui_tga_imebg,"other\\ui\\panel\\imebg",true,true);*/

	/*g_mgui_mouse = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_mgui_mouse,"gfx\\ui\\mouse\\mouse",true,true);*/
	// HOOK
	g_mgui_mouse = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_mgui_mouse,"gfx\\ui\\mouse\\mouse",true,true);

	g_pSurface->DrawGetTextureSize(g_mgui_mouse,g_mouse_w,g_mouse_h);

	g_hWnd = FindWindow("Valve001", NULL);
	g_OldProc = (WNDPROC)GetWindowLong(g_hWnd,GWL_WNDPROC);
	//SetWindowLong(g_hWnd,GWL_WNDPROC,(LONG)g_NewProc);
	SendMessageA(g_hWnd,WM_SETTEXT,0,(LPARAM)"Counter-Strike BreakThrough Edition");
}
bool MGUI_IsInRect(int x,int w,int y,int h)
{
	int iMouseX,iMouseY;
	gEngfuncs.GetMousePosition( &iMouseX,&iMouseY);
	if( iMouseX>x && iMouseX< x+w && iMouseY>y && iMouseY<y+h) return true;
	return false;
}
void MGUI_FreePanel(MGUI_Panel *pPanel)
{
	MGUI_Base *pNext = (MGUI_Base *)pPanel;
	MGUI_Base *pTemp ;
	if(pNext)
	{
		pTemp = pNext;
		pNext = pNext->pNext;
		delete pTemp;
	}
}
void MGUI_ProcessMessage(void *pPointer)
{
	static int iMoving = 0;
	static int iMousePressedPosX=0;
	static int iMousePressedPosY=0;
	static int iMousePosX=0;
	static int iMousePoxY=0;
	static int iMouseMoveW=0;
	static int iMouseMoveH=0;
	
	gEngfuncs.GetMousePosition( &iMousePosX,&iMousePoxY);	
	// Draw Mouse
	//MH_DrawTGAFunction(g_mgui_mouse,255,255,255,255,iMousePosX,iMousePoxY,1.0f);
	//MH_DrawTGAFunction2(g_mgui_mouse,iMousePosX,iMousePoxY,g_MHTga[g_mgui_mouse].width,g_MHTga[g_mgui_mouse].height,255);
	MGUI_Base *pBase = (MGUI_Base *)pPointer;
	int iClass = pBase->iClass;
	if(iClass == MGUI_PANEL)
	{
		int m_iClosing = ((MGUI_Panel *)pPointer)->m_iClosing;
		int m_bHasClose = ((MGUI_Panel *)pPointer)->m_bHasClose;
		if((g_mgui_mouseevent & ME_LEFTCLICK)  && (!(g_mgui_oldmouseevent & ME_LEFTCLICK)) && MGUI_IsInRect(pBase->x+pBase->w-20,20,pBase->y,20) && !m_iClosing && m_bHasClose)
		{
			((MGUI_Panel *)pPointer)->m_iClosing = 1;
			g_mgui_candraw = 0;
		}
		if(m_iClosing ==1) return;

		if( ((MGUI_Panel *)pPointer)->m_bCanMove == false) return;
		if( (g_mgui_mouseevent & ME_LEFTCLICK)  && (!(g_mgui_oldmouseevent & ME_LEFTCLICK)) && ((MGUI_Panel *)pPointer)->IsInRect())
		{
			iMoving = 1;
		}
		else if( !(g_mgui_mouseevent & ME_LEFTCLICK) ) iMoving = 0;

		if(iMoving)
		{

			if(!iMousePressedPosX)
			{
				gEngfuncs.GetMousePosition( &iMousePressedPosX,&iMousePressedPosY);
				pBase->prevx = pBase->x;
				pBase->prevy = pBase->y;
			}
			iMouseMoveW = iMousePosX - iMousePressedPosX;
			iMouseMoveH = iMousePoxY - iMousePressedPosY;
		}
		else
		{
			pBase->prevx = pBase->prevx + iMouseMoveW;
			pBase->prevy = pBase->prevy + iMouseMoveH;

			iMousePressedPosX = 0;
			iMouseMoveW = 0;
			iMouseMoveH = 0;
		}
		pBase->x = pBase->prevx + iMouseMoveW;
		pBase->y = pBase->prevy + iMouseMoveH;

	}
	else if(iClass == MGUI_TEXTENTRY)
	{
		MGUI_TextEntry *pEntry = (MGUI_TextEntry *)pPointer;
		MGUI_Panel *pEntryPanel = (MGUI_Panel *)pEntry->pParent;
		if ( pEntryPanel->m_iClosing) return;
		if((g_mgui_mouseevent & ME_LEFTCLICK) && pEntry->IsInRect())
		{
			pEntry->m_bHasFocus = true;
		}
		else if(g_mgui_mouseevent & ME_LEFTCLICK) pEntry->m_bHasFocus = false;		
	}
	else if(iClass == MGUI_MENU)
	{
		MGUI_Menu *pMenu = (MGUI_Menu *)pPointer;
		MGUI_Panel *pMenuPanel = (MGUI_Panel *)pMenu->pParent;
		if ( pMenuPanel->m_iClosing) return;
		pMenu->IsInRect();
	}
	else if(iClass == MGUI_BUTTON)
	{
		MGUI_Button *pButton = (MGUI_Button *)pPointer;
		MGUI_Panel *pMenuPanel = (MGUI_Panel *)pButton->pParent;
		if ( pMenuPanel->m_iClosing) return;

		if(g_mgui_keynum == pButton->m_iKey && g_mgui_keynum>=0/* && pButton->m_fNextClick<g_flTime*/) pButton->Click();

		if(pButton->IsInRect())
		{
			pButton->m_iStat = 1;
			if(g_mgui_mouseevent & ME_LEFTCLICK)
			{
				pButton->m_iStat = 2;
				if((g_mgui_mouseevent & ME_LEFTCLICK)  && (!(g_mgui_oldmouseevent & ME_LEFTCLICK)) && pButton->m_fNextClick<g_flTime)
				{
					//pButton->m_fNextClick = g_flTime + 0.2f;
					g_mgui_mouseevent = 0;
					//LogToFile("%f",pButton->m_fNextClick);
					pButton->Click();
				}
			}
			if(g_mgui_mouseevent & ME_RIGHTCLICK)
			{
				if((g_mgui_mouseevent & ME_RIGHTCLICK)  && (!(g_mgui_oldmouseevent & ME_RIGHTCLICK))/* && pButton->m_fNextClick<g_flTime*/)
				{
					//pButton->m_fNextClick = g_flTime + 0.2f;					
					pButton->Click2();
					g_mgui_mouseevent = 0;
				}
			}
		}
		else
		{
			pButton->m_iStat = 0;
		}
	}
}

void MGUI_Redraw()
{	
	//gEngfuncs.pfnFillRGBA(0,0,62.5,10,0,188,240,255);
	if(g_mgui_candraw || g_iMenuActive)
	{
		iCanSetMouse = 1;
		//ShowCursor(false);
		gExportfuncs.IN_DeactivateMouse();		

		BTEPanel_BuyMenu_SetTime();
	}
	else
	{
		if (iCanSetMouse)
		{
			SetCursorPos ( gEngfuncs.GetWindowCenterX(), gEngfuncs.GetWindowCenterY() );
			iCanSetMouse = 0;
		}		
		gExportfuncs.IN_ActivateMouse();
		if(g_iMini)
			UI_Draw();
		//ShowCursor(true);
		return;
	}
	if(g_iMenuActive)
	{
		UI_Draw();
		return;
	}

	//MGUI_Base *pNextControl = pRootPanel;
	MGUI_Panel *pSubPanel = pRootPanel;
	// Draw Panel
	while (pSubPanel)
	{
		MGUI_Base *pNextControl = pSubPanel;		
		
		// Draw X
		if( !(pSubPanel->m_iClosing))
		{
		MGUI_ProcessMessage(pSubPanel);
		//MH_DrawTGAFunction2(pSubPanel->m_iTexture,pSubPanel->x,pSubPanel->y,pSubPanel->w,pSubPanel->h,255);
		if(pSubPanel->m_iHaveBg) MH_DrawTGA_9(pSubPanel->m_iTexture, pSubPanel->x, pSubPanel->y, pSubPanel->w, pSubPanel->h, 255);
		
		if(pSubPanel->m_bHasClose)
		{
			Fonts_SetSize(12,12);
			Fonts_SetColor(255,0,0,255);
			Fonts_Draw(L"X",pSubPanel->x+pSubPanel->w-20,pSubPanel->y+20,100,100);
		}
		// Set Title
		if(pSubPanel->m_pTitle)
		{
			Fonts_SetSize(pSubPanel->m_iTitleSize,pSubPanel->m_iTitleSize);
			int iLen = Fonts_GetLen(pSubPanel->m_pTitle);
			int iStartX = pSubPanel->x+(pSubPanel->w - iLen) / 2;			
			Fonts_SetColor(255,255,255,255);
			Fonts_Draw(pSubPanel->m_pTitle,iStartX,pSubPanel->y+30,1000,1000);
		}
		// Draw Sub Control
		while(pNextControl->pNext)
		{
			MGUI_ProcessMessage(pNextControl->pNext);
			pNextControl->pNext->Paint(pSubPanel);
			pNextControl = pNextControl->pNext;
		}
		}
		pSubPanel = pSubPanel->pNextPanel;
	}

	int iMousePosX=0;
	int iMousePoxY=0;
	gEngfuncs.GetMousePosition( &iMousePosX,&iMousePoxY);

	MH_DrawTGAFunction2(g_mgui_mouse,iMousePosX,iMousePoxY,g_mouse_w,g_mouse_h,255);


}

void MGUI_ShutDown(void)
{
	return;
}