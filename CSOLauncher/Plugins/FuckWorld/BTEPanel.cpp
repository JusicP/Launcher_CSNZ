#include "base.h"

// TDM UI
MGUI_Panel *pTeamSuitPanel;
// -- 记录可以改变的标签指针 共12个
MGUI_Label *pTeamSuitLabel[24];
// -- 记录可以改变的图片指针 共12个
MGUI_Image *pTeamSuitImage[12];
MGUI_Image *pTeamSuitImage2[12];
// -- 记录按钮 共4个
MGUI_Button *pTeamSuitButton[4];

// BUY MENU
char MENU[10][32]={"CSBTE_BUYMENUPANEL_PISTOL","CSBTE_BUYMENUPANEL_SHOTGUN","CSBTE_BUYMENUPANEL_SMG","CSBTE_BUYMENUPANEL_RIFLE",
					"CSBTE_BUYMENUPANEL_MG","CSBTE_BUYMENUPANEL_PRIMAMMO","CSBTE_BUYMENUPANEL_SECAMMO","CSBTE_BUYMENUPANEL_EQUIP",
					"CSBTE_BUYMENUPANEL_KNIFE","CSBTE_BUYMENUPANEL_EXIT"};
char CMD[10][32]={"bte_wpn_menu_gui 0 %d","bte_wpn_menu_gui 1 %d","bte_wpn_menu_gui 2 %d","bte_wpn_menu_gui 3 %d",
					"bte_wpn_menu_gui 4 %d","primammo","secammo",/*"MGUI.BuyMenu_ShowEquipMenu"*/"bte_wpn_menu_gui 5 %d",
					"bte_wpn_menu_gui 6 %d",""};
char WEAPON_INFO[7][64]={"CSBTE_BUYMENU_WEAPONINFO_DAMAGE","CSBTE_BUYMENU_WEAPONINFO_HITRATE","CSBTE_BUYMENU_WEAPONINFO_REACTION",
						"CSBTE_BUYMENU_WEAPONINFO_FIRINGSPEED","CSBTE_BUYMENU_WEAPONINFO_WEIGHT","CSBTE_BUYMENU_WEAPONINFO_COST",
						"CSBTE_BUYMENU_WEAPONINFO_BPAMMO",};
char WEAPON_INFO_INI[7][16]={"Damage","HitRate","Reaction","FiringSpeed","Weight","Cost","BpAmmo",};
char QUICKBUY_INI[4][16]={"Primary","Secondary","Knife","Grenade"};

MGUI_Panel *pBuyMenuPanel;
MGUI_Label *pBuyMenuLabel[10];
MGUI_Label *pBuyMenuLabelKey[10];
MGUI_Button *pBuyMenuButton[10];
MGUI_Button *pBuyMenuButton2[2];
MGUI_Button *pBuyMenuButtonPage[2];
MGUI_Image *pBuyMenuImage[10];
MGUI_Image *pBuyMenuImageWpn[10];

//MGUI_Image *pBuyMenuImageQuickBuy[10];
MGUI_Image *pBuyMenuImageQuickBuy[2][5];
//MGUI_Image *pBuyMenuImageFav[5];
//MGUI_Image *pBuyMenuImageFavBg[5];
MGUI_Image *pBuyMenuImageFavWpn[5][3];
MGUI_Image *pBuyMenuImageFavKey[5];
MGUI_Label *pBuyMenuLabelFavKey[10];
MGUI_Button *pBuyMenuButtonFav[5];

MGUI_Button *pBuyMenuButtonSlot[2];
MGUI_Label *pBuyMenuLabelSlot;
MGUI_Image *pBuyMenuImageSlot;

MGUI_Image *pBuyMenuPanelImageTimer[2];
MGUI_Label *pBuyMenuPanelLabelTimer[2];
MGUI_Label *pBuyMenuPanelLabelTimer2[2];

MGUI_Panel *pBuyMenuPanel_WpnInfo[10];
MGUI_Image *pBuyMenuPanelImage_WpnInfo[10][2];
MGUI_Image *pBuyMenuPanelImage_WpnInfo_Line[10][5];
MGUI_Label *pBuyMenuPanelLabel_WpnInfo[10][7][2];

MGUI_Button *pBuyMenuButtonBuy;
MGUI_Button *pBuyMenuButtonClose;

int iPage = 0;
int iType = 0;

int iTDMSlot = 0;

char configPath[128];
char configPathFavWpn[128];
char configPathTeamSuit[128];
bool bFirst = true;

char szFavWpn[6][4][32];
char szTeamSuitWpn[3][4][32];

int g_UI_Panel[3][3];
int g_UI_Panel_Dark[3][3];
int g_UI_Output[3][3];
int g_UI_Button[3][3];
int g_UI_Button_Glow[3][3];
int g_UI_Panel_Gray[3][3];
int g_UI_Panel_TeamSuit[3][3];

void BTEPanel_BuyMenu_First();
int	BTEPanel_BuyMenu_Read(int iSolt);
void BTEPanel_TeamSuit_Read(int iSlot);

void BTEPanel_TeamSuit_Reset()
{
	bFirst = true;
	pTeamSuitButton[0]->m_fNextClick = 0.0f;
	pTeamSuitButton[1]->m_fNextClick = 0.0f;
	pTeamSuitButton[2]->m_fNextClick = 0.0f;
	pTeamSuitButton[3]->m_fNextClick = 0.0f;
}
void BTEPanel_TeamSuit_Save(void)
{
	char szText[16];
	sprintf(szText,"TeamSuit%d",iTDMSlot+1);
	for(int i=0;i<=3;i++)
	{
		WritePrivateProfileString(szText,QUICKBUY_INI[i],szFavWpn[5][i],configPathTeamSuit);
	}
	char szCmd[256];
	//sprintf(szCmd,"bte_dm_set_weapon 0 %s;wait;bte_dm_set_weapon 1 %s;wait;bte_dm_set_weapon 2 %s;wait;bte_dm_set_weapon 3 %s;wait;bte_dm_buy1",szFavWpn[5][0],szFavWpn[5][1],szFavWpn[5][2],szFavWpn[5][3]);
	sprintf(szCmd,"bte_dm_set_weapon %s %s %s %s;bte_dm_buy1",szFavWpn[5][0],szFavWpn[5][1],szFavWpn[5][2],szFavWpn[5][3]);

	BTEPanel_TeamSuit_UpdateItems(iTDMSlot,szFavWpn[5][0],szFavWpn[5][1],szFavWpn[5][2],szFavWpn[5][3]);
	pTeamSuitButton[iTDMSlot+1]->SetCommand(szCmd);

	BTEPanel_TeamSuit_Show();
}
void BTEPanel_TeamSuit_Show(void)
{
	pTeamSuitPanel->m_iClosing = 0;
	pBuyMenuPanel->m_iClosing = 1;
	for(int i=0;i<=9;i++) pBuyMenuPanel_WpnInfo[i]->m_iClosing = 1;
	g_mgui_candraw = 1;

	for(int i=0; i<=2; i++)
	{
		if(g_iWeaponLimit == 0 || g_iWeaponLimit == 1)
			pTeamSuitImage2[i]->SetVisible(false);
		else
			pTeamSuitImage2[i]->SetVisible(true);

		if(g_iWeaponLimit == 0 || g_iWeaponLimit == 2)
			pTeamSuitImage2[i + 3]->SetVisible(false);
		else
			pTeamSuitImage2[i + 3]->SetVisible(true);

		if(g_iWeaponLimit == 0 || g_iWeaponLimit == 3)
			pTeamSuitImage2[i + 9]->SetVisible(false);
		else
			pTeamSuitImage2[i + 9]->SetVisible(true);

		pTeamSuitImage2[i + 6]->SetVisible(false);
	}
}

void BTEPanel_TeamSuit_SetSlot(int iSlot)
{
	iTDMSlot += iSlot;
	if(iTDMSlot == 3) iTDMSlot = 0;
	if(iTDMSlot == -1) iTDMSlot = 2;
	char szText[32];
	sprintf(szText,"CSBTE_TEAMSUITPANEL_SUIT%d",iTDMSlot+1);
	pBuyMenuLabelSlot->SetLabel(GetLangUni(szText));
}
void BTEPanel_TeamSuit_UpdateItems(int iSlot,char *pItems1,char *pItems2,char *pItems3,char *pItem4)
{
	char szTga[64];

	sprintf(szTga,"gfx\\vgui\\%s",pItems1);
	pTeamSuitImage[iSlot]->SetTexture(szTga);
	sprintf(szTga,"CSBTE_%s",pItems1);
	pTeamSuitLabel[iSlot]->SetLabel(GetLangUni(strupr(szTga)));

	sprintf(szTga,"gfx\\vgui\\%s",pItems2);
	pTeamSuitImage[iSlot + 3]->SetTexture(szTga);
	sprintf(szTga,"CSBTE_%s",pItems2);
	pTeamSuitLabel[iSlot + 3]->SetLabel(GetLangUni(strupr(szTga)));

	sprintf(szTga,"gfx\\vgui\\%s",pItems3);
	pTeamSuitImage[iSlot + 6]->SetTexture(szTga);
	sprintf(szTga,"CSBTE_%s",pItems3);
	pTeamSuitLabel[iSlot + 6]->SetLabel(GetLangUni(strupr(szTga)));

	sprintf(szTga,"gfx\\vgui\\%s",pItem4);
	pTeamSuitImage[iSlot + 9]->SetTexture(szTga);
	sprintf(szTga,"CSBTE_%s",pItem4);
	pTeamSuitLabel[iSlot + 9]->SetLabel(GetLangUni(strupr(szTga)));	

			
	/*pTeamSuitPanel->m_iClosing = 0;
	pBuyMenuPanel->m_iClosing = 1;
	for(int i=0;i<=9;i++) pBuyMenuPanel_WpnInfo[i]->m_iClosing = 1;*/

}
void BTEPanel_TeamSuit_Read(int iSlot)
{
	char name[16];
	sprintf(name,"TeamSuit%d",iSlot+1);
	for(int i=0;i<=3;i++)
	{
		char value[1024];
		GetPrivateProfileStringA(name,QUICKBUY_INI[i],"",value,sizeof(value),configPathTeamSuit);
		if(strlen(value))
		{
			sprintf(szTeamSuitWpn[iSlot][i],"%s",value);
			char wpnname[64];
			sprintf(wpnname,"gfx\\vgui\\%s",value);
			pTeamSuitImage[iSlot + i * 3]->SetTexture(wpnname);
			char text[64];
			sprintf(text,"CSBTE_%s",value);
			pTeamSuitLabel[iSlot + i * 3]->SetLabel(GetLangUni(text));
		}
	}
	char szCmd[256];
	//sprintf(szCmd,"bte_dm_set_weapon 0 %s;wait;bte_dm_set_weapon 1 %s;wait;bte_dm_set_weapon 2 %s;wait;bte_dm_set_weapon 3 %s;wait;bte_dm_buy1",szTeamSuitWpn[iSlot][0],szTeamSuitWpn[iSlot][1],szTeamSuitWpn[iSlot][2],szTeamSuitWpn[iSlot][3]);
	sprintf(szCmd,"bte_dm_set_weapon %s %s %s %s;bte_dm_buy1",szTeamSuitWpn[iSlot][0],szTeamSuitWpn[iSlot][1],szTeamSuitWpn[iSlot][2],szTeamSuitWpn[iSlot][3]);
	pTeamSuitButton[iSlot + 1]->SetCommand(szCmd);

}
void BTEPanel_Init(void)
{
	strcpy(configPath,"metahook/weapons.ini");
	strcpy(configPathFavWpn,"metahook/quickbuy.ini");
	strcpy(configPathTeamSuit,"metahook/teamsuit.ini");


	LoadTga_9(g_UI_Panel,"window");
	LoadTga_9(g_UI_Panel_Dark,"window_dark");
	LoadTga_9(g_UI_Output,"output");
	LoadTga_9(g_UI_Panel_Gray,"gray");
	LoadTga_9(g_UI_Panel_TeamSuit,"teamsuit");

	LoadTga_3(g_UI_Button[0],"button\\n");
	LoadTga_3(g_UI_Button[1],"button\\o");
	LoadTga_3(g_UI_Button[2],"button\\c");

	LoadTga_3(g_UI_Button_Glow[0],"button_glow\\n");
	LoadTga_3(g_UI_Button_Glow[1],"button_glow\\o");
	LoadTga_3(g_UI_Button_Glow[2],"button_glow\\c");


	// 初始化团队套装
	pTeamSuitPanel = MGUI_CreatePanel(50,100,602,550,20,true/*是否可以移动*/);
	//pTeamSuitPanel->SetTexture("");
	wcscpy(pTeamSuitPanel->m_pTitle,GetLangUni("CSBTE_TEAMSUITPANEL_TITLE"));
	pTeamSuitPanel->m_iTitleSize = 16;
	pTeamSuitPanel->m_bHasClose = false; // 是否提供X关闭面板
	//pTeamSuitPanel->pNextPanel = 0x0;

	//
	pTeamSuitButton[0] = MGUI_CreateButton(pTeamSuitPanel,230,450,150,32);
	pTeamSuitButton[0]->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_EDIT"));
	pTeamSuitButton[0]->SetCommand("MGUI.ShowBuyMenu");
	pTeamSuitButton[0]->SetType(MGUI_BUTTON_TYPE_COMMAND_CLOSEPANEL);
	pTeamSuitButton[0]->m_iSize = 14;
	pTeamSuitButton[0]->SetKey('e');
	//pTeamSuitButton[0]->SetImage3(g_UI_Button);	
	memcpy(pTeamSuitButton[0]->iTga3,g_UI_Button,sizeof(g_UI_Button));
	pTeamSuitButton[0]->m_Tex_Type = MGUI_TEX_TYPE_3;
	
	// 标题 第一行
	int iX = 60;
	int iY = 60;

	MGUI_Label *pLabel = MGUI_CreateLabel(pTeamSuitPanel,iX+20,iY,100,20);
	pLabel->SetColor(255,251,219,255);
	pLabel->SetSize(14);
	pLabel->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_SUIT1"));
	// 背景图	
	MGUI_Image *pImage= MGUI_CreateImage(pTeamSuitPanel,iX-35 ,iY-10,180 ,382,true,false);
	pImage->m_iTex_Type =  MGUI_TEX_TYPE_9;
	memcpy(pImage->m_iTexture9,g_UI_Panel_Gray,sizeof(g_UI_Panel_Gray));

	pTeamSuitButton[1] = MGUI_CreateButton(pTeamSuitPanel,iX - 35 ,iY - 10,180,382);
	pTeamSuitButton[1]->SetCommand("");
	pTeamSuitButton[1]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
	//pTeamSuitButton[1]->SetImage("","other\\ui\\panel\\equipbg","other\\ui\\panel\\equipbg");
	pTeamSuitButton[1]->m_Tex_Type = MGUI_TEX_TYPE_9;
	memcpy(pTeamSuitButton[1]->iTga9[1],g_UI_Panel_TeamSuit,sizeof(g_UI_Panel_TeamSuit));
	memcpy(pTeamSuitButton[1]->iTga9[2],g_UI_Panel_TeamSuit,sizeof(g_UI_Panel_TeamSuit));
	//pTeamSuitButton[1]->iTga[1] = pTeamSuitButton[1]->iTga[2] = DrawTgaGetID("other\\ui\\panel\\equipbg");
	pTeamSuitButton[1]->SetKey('1');

	iX += 185;
	pLabel = MGUI_CreateLabel(pTeamSuitPanel,iX+20,iY,100,20);
	pLabel->SetColor(255,251,219,255);
	pLabel->SetSize(14);
	pLabel->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_SUIT2"));
	pImage= MGUI_CreateImage(pTeamSuitPanel,iX - 35 ,iY - 10,180,382,true,false);
	pImage->m_iTex_Type =  MGUI_TEX_TYPE_9;
	memcpy(pImage->m_iTexture9,g_UI_Panel_Gray,sizeof(g_UI_Panel_Gray));
	pTeamSuitButton[2] = MGUI_CreateButton(pTeamSuitPanel,iX - 35 ,iY - 10,180,382);
	pTeamSuitButton[2]->SetCommand("");
	pTeamSuitButton[2]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
	//pTeamSuitButton[2]->SetImage("","other\\ui\\panel\\equipbg","other\\ui\\panel\\equipbg");
	pTeamSuitButton[2]->m_Tex_Type = MGUI_TEX_TYPE_9;
	memcpy(pTeamSuitButton[2]->iTga9[1],g_UI_Panel_TeamSuit,sizeof(g_UI_Panel_TeamSuit));
	memcpy(pTeamSuitButton[2]->iTga9[2],g_UI_Panel_TeamSuit,sizeof(g_UI_Panel_TeamSuit));	
	//pTeamSuitButton[2]->iTga[1] = pTeamSuitButton[2]->iTga[2] = DrawTgaGetID("other\\ui\\panel\\equipbg");
	pTeamSuitButton[2]->SetKey('2');

	iX += 185;
	pLabel = MGUI_CreateLabel(pTeamSuitPanel,iX+20,iY,100,20);
	pLabel->SetColor(255,251,219,255);
	pLabel->SetSize(14);
	pLabel->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_SUIT3"));
	pImage= MGUI_CreateImage(pTeamSuitPanel,iX-35,iY-10,180,382,true,false);
	pImage->m_iTex_Type =  MGUI_TEX_TYPE_9;
	memcpy(pImage->m_iTexture9,g_UI_Panel_Gray,sizeof(g_UI_Panel_Gray));
	pTeamSuitButton[3] = MGUI_CreateButton(pTeamSuitPanel,iX-35,iY-10,180,381);
	pTeamSuitButton[3]->SetCommand("");
	pTeamSuitButton[3]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
	//pTeamSuitButton[3]->SetImage("","other\\ui\\panel\\equipbg","other\\ui\\panel\\equipbg");
	pTeamSuitButton[3]->m_Tex_Type = MGUI_TEX_TYPE_9;
	memcpy(pTeamSuitButton[3]->iTga9[1],g_UI_Panel_TeamSuit,sizeof(g_UI_Panel_TeamSuit));
	memcpy(pTeamSuitButton[3]->iTga9[2],g_UI_Panel_TeamSuit,sizeof(g_UI_Panel_TeamSuit));
	//pTeamSuitButton[3]->iTga[1] = pTeamSuitButton[3]->iTga[2] = DrawTgaGetID("other\\ui\\panel\\equipbg");
	pTeamSuitButton[3]->SetKey('3');

	// 图片背景 及内容
	int iDefineX = 34;
	int iDefineY = iY + 23; // 45
	// 共12 个

	for(int iLine = 0; iLine <4;iLine++)
	{
		for(int iRow = 0 ; iRow <3 ; iRow++)
		{
			iX = iRow * 185 + iDefineX;
			iY = iDefineY + 85* iLine; // iY = iDefineY + 100* iLine;

			
			// -- 下面的武器名字
			pTeamSuitLabel[iLine*3 + iRow] = MGUI_CreateLabel(pTeamSuitPanel,iX+5,iY+63,164,20);
			pTeamSuitLabel[iLine*3 + iRow]->SetColor(255,255,255,255);
			pTeamSuitLabel[iLine*3 + iRow]->SetSize(14);
			pTeamSuitLabel[iLine*3 + iRow]->SetLabel(L"");

			pTeamSuitLabel[iLine*3 + iRow + 12] = MGUI_CreateLabel(pTeamSuitPanel,iX+8,iY+40,164,20);
			pTeamSuitLabel[iLine*3 + iRow + 12]->SetColor(128,128,128,255);
			pTeamSuitLabel[iLine*3 + iRow + 12]->SetSize(13);

			pImage= MGUI_CreateImage(pTeamSuitPanel,iX,iY,164,63,true,false);
			pImage->SetTexture("gfx\\ui\\panel\\equipslot");
			pTeamSuitImage[iLine*3 + iRow]= MGUI_CreateImage(pTeamSuitPanel,iX+7,iY+4,150,53,true,false);// 武器tga
			pTeamSuitImage[iLine*3 + iRow]->m_iTexture = 0;

			pTeamSuitImage2[iLine*3 + iRow]= MGUI_CreateImage(pTeamSuitPanel,iX+7,iY+4,150,53,true,false);// 武器tga
			pTeamSuitImage2[iLine*3 + iRow]->SetTexture("gfx\\vgui\\cannotuse");
			pTeamSuitImage2[iLine*3 + iRow]->SetVisible(true);
			//pTeamSuitImage[iLine*3 + iRow]->SetTexture("gfx\\vgui\\cannotuse");
		}
	}

	for(int i=0;i<=2;i++)
	{

		pTeamSuitLabel[i + 12]->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_PRIMARY"));
		pTeamSuitLabel[i + 3 + 12]->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_SECONDARY"));
		pTeamSuitLabel[i + 6 + 12]->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_KNIFE"));				
		pTeamSuitLabel[i + 9 + 12]->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_GRENADE"));

		BTEPanel_TeamSuit_Read(i);
	}

	/*for(int iLine = 0; iLine <4;iLine++)
	{
		for(int iRow = 0 ; iRow <3 ; iRow++)
		{
			iX = iRow * 185 + iDefineX;
			iY = iDefineY + 85* iLine;
			pTeamSuitLabel[iLine*3 + iRow + 12] = MGUI_CreateLabel(pTeamSuitPanel,iX+8,iY+40,164,20);
			pTeamSuitLabel[iLine*3 + iRow + 12]->SetColor(128,128,128,255);
			pTeamSuitLabel[iLine*3 + iRow + 12]->SetSize(13);
			
			
		}
		for(int iRow = 0 ; iRow <3 ; iRow++)
		{
			iX = iRow * 175 + iDefineX;
			iY = iDefineY + 85* iLine; // iY = iDefineY + 100* iLine;
			// -- 下面的武器名字
			pTeamSuitLabel[iLine*3 + iRow] = MGUI_CreateLabel(pTeamSuitPanel,iX+5,iY+63,100,20);
			pTeamSuitLabel[iLine*3 + iRow]->SetColor(255,255,255,255);
			pTeamSuitLabel[iLine*3 + iRow]->SetSize(16);
			pTeamSuitLabel[iLine*3 + iRow]->SetLabel(L"");
		}
	}*/
	// 为什么不提供一个输入框呢 SB
	// MGUI_TextEntry *pTextEntry = MGUI_CreateTextEntry(pTeamSuitPanel,100,100,300);
}
void BTEBuyMenu_Init(void)
{
	memset(szFavWpn,0,sizeof(szFavWpn));

	sprintf(szFavWpn[5][0],"mp5");
	sprintf(szFavWpn[5][1],"usp");
	sprintf(szFavWpn[5][2],"knife");
	sprintf(szFavWpn[5][3],"hegrenade");

	char name[16];
	sprintf(name,"QuickBuy%d",0);
	for(int i=0;i<=4;i++)
	{
		GetPrivateProfileStringA(name,QUICKBUY_INI[i],"",szFavWpn[5][i],sizeof(szFavWpn[5][i]),configPathFavWpn);		
		if(strlen(szFavWpn[5][i]))
		{
			char wpnname[64];
			sprintf(wpnname,"gfx\\vgui\\%s",szFavWpn[5][i]);
		}
	}

	pBuyMenuPanel = MGUI_CreatePanel(0, 0, 0, 0, 22, false);
	
	//pBuyMenuPanel->SetTexture();
	wcscpy(pBuyMenuPanel->m_pTitle,GetLangUni("CSBTE_BUYMENUPANEL_TITLE"));
	pBuyMenuPanel->m_iTitleSize = 18;
	pBuyMenuPanel->m_bHasClose = false;	

	for(int i=0;i<=9;i++)
	{
		
		pBuyMenuPanel_WpnInfo[i] = MGUI_CreatePanel(100, 100, 200, 200, 22, false);
		//pBuyMenuPanel_WpnInfo[i]->SetTexture();
		//wcscpy(pBuyMenuPanel_WpnInfo->m_pTitle,);
		pBuyMenuPanel_WpnInfo[i]->m_pTitle[0] = '\0';
		pBuyMenuPanel_WpnInfo[i]->m_iTitleSize = 18;
		pBuyMenuPanel_WpnInfo[i]->m_bHasClose = false;
		pBuyMenuPanel_WpnInfo[i]->m_iHaveBg = 0;
		
		pBuyMenuPanelImage_WpnInfo[i][0] = MGUI_CreateImage(pBuyMenuPanel_WpnInfo[i],0 ,0, 0, 0, true, false);
		pBuyMenuPanelImage_WpnInfo[i][0]->m_iTex_Type = MGUI_TEX_TYPE_9;
		//pBuyMenuPanelImage_WpnInfo[i][0]->SetTexture("other\\ui\\panel\\weapon_info_bg");
		memcpy(pBuyMenuPanelImage_WpnInfo[i][0]->m_iTexture9,g_UI_Panel_Gray,sizeof(g_UI_Panel_Gray));
		pBuyMenuPanelImage_WpnInfo[i][1] = MGUI_CreateImage(pBuyMenuPanel_WpnInfo[i],0 ,0, 0, 0, false, false);

		for(int j=0;j<=4;j++)
		{
			pBuyMenuPanelImage_WpnInfo_Line[i][j] = MGUI_CreateImage(pBuyMenuPanel_WpnInfo[i],0 ,0, 0, 0, true, false);
			pBuyMenuPanelImage_WpnInfo_Line[i][j]->SetTexture("gfx\\ui\\panel\\weapon_info_line");
		}
		for(int j=0;j<=6;j++)
		{
			for(int k=0;k<=1;k++)
			{
				pBuyMenuPanelLabel_WpnInfo[i][j][k] = MGUI_CreateLabel(pBuyMenuPanel_WpnInfo[i],0,0,0,0);
				pBuyMenuPanelLabel_WpnInfo[i][j][k]->SetSize(14);
				pBuyMenuPanelLabel_WpnInfo[i][j][k]->SetColor(200,200,200,255);
				pBuyMenuPanelLabel_WpnInfo[i][j][k]->h = 14;
			}
			pBuyMenuPanelLabel_WpnInfo[i][j][0]->SetLabel(GetLangUni(WEAPON_INFO[j]));
			pBuyMenuPanelLabel_WpnInfo[i][j][1]->SetLabel(GetLangUni(WEAPON_INFO[j]));
		}
		pBuyMenuPanelImage_WpnInfo[i][1]->m_iTexture = 0;

		pBuyMenuButton[i] = MGUI_CreateButton(pBuyMenuPanel,0,0,0,0);
		pBuyMenuButton[i]->SetImage("gfx\\ui\\panel\\blank_slot","gfx\\ui\\panel\\select","gfx\\ui\\panel\\select");		

		pBuyMenuImage[i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		pBuyMenuImage[i]->SetTexture("gfx\\ui\\panel\\key");

		pBuyMenuImageWpn[i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		pBuyMenuImageWpn[i]->SetVisible(false);

		pBuyMenuLabelKey[i] = MGUI_CreateLabel(pBuyMenuPanel,0,0,0,0);
		pBuyMenuLabelKey[i]->SetSize(14);
		pBuyMenuLabelKey[i]->SetColor(255,255,255,255);
		char num[2];
		int n;
		n = i + 1;
		if(n == 10) n = 0;
		sprintf(num,"%d",n);
		wchar_t pWchar[2];
		Fonts_C2W(pWchar,2,num);
		pBuyMenuLabelKey[i]->SetLabel(pWchar);
		pBuyMenuButton[i]->SetKey(num[0]);

		pBuyMenuLabel[i] = MGUI_CreateLabel(pBuyMenuPanel,0,0,286,43);	
		pBuyMenuLabel[i]->SetSize(14);

	}
	

	for(int i=0;i<=1;i++)
	{
		pBuyMenuButtonPage[i] = MGUI_CreateButton(pBuyMenuPanel,0,0,0,0);
		pBuyMenuButtonPage[i]->SetType(MGUI_BUTTON_TYPE_COMMAND);
		pBuyMenuButtonPage[i]->SetVisible(false);
		//pBuyMenuButtonPage[i]->SetImage3(g_UI_Button);
		memcpy(pBuyMenuButtonPage[i]->iTga3,g_UI_Button,sizeof(g_UI_Button));
		pBuyMenuButtonPage[i]->m_iSize = 14;
		pBuyMenuButtonPage[i]->m_Tex_Type = MGUI_TEX_TYPE_3;

		pBuyMenuButton2[i] = MGUI_CreateButton(pBuyMenuPanel,0,0,0,0);
		pBuyMenuButton2[i]->SetType(MGUI_BUTTON_TYPE_COMMAND);
		pBuyMenuButton2[i]->SetColor(195,221,255,255);
		//pBuyMenuButton2[i]->SetImage3(g_UI_Button_Glow);
		memcpy(pBuyMenuButton2[i]->iTga3,g_UI_Button_Glow,sizeof(g_UI_Button_Glow));
		pBuyMenuButton2[i]->m_iSize = 14;
		pBuyMenuButton2[i]->m_Tex_Type = MGUI_TEX_TYPE_3;
		pBuyMenuButton2[i]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
		pBuyMenuButton2[i]->m_iOffset[0] = 2;

		pBuyMenuPanelImageTimer[i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		pBuyMenuPanelImageTimer[i]->m_iTex_Type = MGUI_TEX_TYPE_9;
		memcpy(pBuyMenuPanelImageTimer[i]->m_iTexture9,g_UI_Output,sizeof(g_UI_Output));

		pBuyMenuPanelLabelTimer[i] = MGUI_CreateLabel(pBuyMenuPanel,0,0,0,0);
		pBuyMenuPanelLabelTimer[i]->SetColor(200,200,200,255);
		pBuyMenuPanelLabelTimer[i]->SetSize(14);

		pBuyMenuPanelLabelTimer2[i] = MGUI_CreateLabel(pBuyMenuPanel,0,0,0,0);
		pBuyMenuPanelLabelTimer2[i]->SetColor(200,200,200,255);
		pBuyMenuPanelLabelTimer2[i]->SetSize(14);
		pBuyMenuPanelLabelTimer2[i]->m_iAlignment = MGUI_Right;
	}
	pBuyMenuPanelLabelTimer[0]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_MONEY"));
	pBuyMenuPanelLabelTimer[1]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_BUY_TIME"));

	pBuyMenuButtonPage[0]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_PREV_PAGE"));
	pBuyMenuButtonPage[1]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_NEXT_PAGE"));

	pBuyMenuButton2[0]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_REBUY"));
	pBuyMenuButton2[1]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_AUTOBUY"));
	pBuyMenuButton2[0]->SetCommand("bte_wpn_rebuy");
	pBuyMenuButton2[0]->SetKey('r');
	pBuyMenuButton2[1]->SetKey('a');

	pBuyMenuButtonPage[0]->SetKey(173); //K_KP_SLASH
	pBuyMenuButtonPage[1]->SetKey(174); //K_KP_PLUS
	

	for(int i=0;i<=4;i++)
	{
		/*pBuyMenuImageFavBg[i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		pBuyMenuImageFavBg[i]->SetTexture("other\\ui\\panel\\blank_slot");*/

		/*pBuyMenuImageFav[i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		pBuyMenuImageFav[i]->SetTexture("other\\ui\\panel\\blank_slot");*/
		//pBuyMenuImageFav[i]->SetVisible(false);

		pBuyMenuButtonFav[i] = MGUI_CreateButton(pBuyMenuPanel, 0, 0, 0, 0);

		pBuyMenuImageFavKey[i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		pBuyMenuImageFavKey[i]->SetTexture("gfx\\ui\\panel\\key");

		pBuyMenuLabelFavKey[i] = MGUI_CreateLabel(pBuyMenuPanel, 0, 0, 0, 0);
		pBuyMenuLabelFavKey[i]->SetSize(14);

		pBuyMenuImageQuickBuy[0][i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		pBuyMenuImageQuickBuy[1][i] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
		//pBuyMenuImageQuickBuy[1][i]->SetTexture("");

		for(int j=0;j<=2;j++)
		{
			pBuyMenuImageFavWpn[i][j] = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
			pBuyMenuImageFavWpn[i][j]->m_iTexture = -1;
		}

		
		pBuyMenuButtonFav[i]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
		pBuyMenuButtonFav[i]->SetEnabled(false);
		pBuyMenuButtonFav[i]->SetImage("gfx\\ui\\panel\\blank_slot","gfx\\ui\\panel\\blank_slot","gfx\\ui\\panel\\blank_slot");
		char szCmd[64];
		sprintf(szCmd,"MGUI.BuyMenu_SaveFav %d",i);
		pBuyMenuButtonFav[i]->SetCommand2(szCmd);		

		if(BTEPanel_BuyMenu_Read(i))
		{
			pBuyMenuButtonFav[i]->SetImage("gfx\\ui\\panel\\favoritebg","gfx\\ui\\panel\\select","gfx\\ui\\panel\\select");
			//pBuyMenuImageFav[i]->SetTexture("other\\ui\\panel\\favoritebg");
			pBuyMenuButtonFav[i]->SetEnabled(true);
		}
	}
	pBuyMenuImageQuickBuy[0][0]->SetTexture("gfx\\ui\\panel\\blank_slot_priweapons");
	pBuyMenuImageQuickBuy[0][1]->SetTexture("gfx\\ui\\panel\\blank_slot_flashbangs");
	pBuyMenuImageQuickBuy[0][2]->SetTexture("gfx\\ui\\panel\\blank_slot_sndweapons");
	pBuyMenuImageQuickBuy[0][3]->SetTexture("gfx\\ui\\panel\\blank_slot_equipment");
	pBuyMenuImageQuickBuy[0][4]->SetTexture("gfx\\ui\\panel\\basket_blank_slot");

	pBuyMenuLabelFavKey[0]->SetLabel(L"S");
	pBuyMenuLabelFavKey[1]->SetLabel(L"D");
	pBuyMenuLabelFavKey[2]->SetLabel(L"F");
	pBuyMenuLabelFavKey[3]->SetLabel(L"G");
	pBuyMenuLabelFavKey[4]->SetLabel(L"H");

	pBuyMenuButtonFav[0]->SetKey('s');
	pBuyMenuButtonFav[1]->SetKey('d');
	pBuyMenuButtonFav[2]->SetKey('f');
	pBuyMenuButtonFav[3]->SetKey('g');
	pBuyMenuButtonFav[4]->SetKey('h');

	char szImg[64];
	sprintf(szImg,"gfx\\vgui\\%s",szFavWpn[5][0]);
	pBuyMenuImageQuickBuy[1][0]->SetTexture(szImg);
	sprintf(szImg,"gfx\\vgui\\%s",szFavWpn[5][1]);
	pBuyMenuImageQuickBuy[1][1]->SetTexture(szImg);
	sprintf(szImg,"gfx\\vgui\\%s",szFavWpn[5][3]);
	pBuyMenuImageQuickBuy[1][2]->SetTexture(szImg);
	pBuyMenuImageQuickBuy[1][3]->SetTexture("gfx\\vgui\\vesthelm");
	sprintf(szImg,"gfx\\vgui\\%s",szFavWpn[5][2]);
	pBuyMenuImageQuickBuy[1][4]->SetTexture(szImg);
	
	pBuyMenuButtonBuy = MGUI_CreateButton(pBuyMenuPanel,0,0,0,0);
	pBuyMenuButtonBuy->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
	pBuyMenuButtonBuy->SetColor(195,221,255,255);
	//pBuyMenuButtonBuy->SetCommand("bte_buy_wpn mp5;bte_buy_wpn usp;bte_buy_wpn hegrenade;bte_buy_wpn knife;secammo;primammo");
	
	char szCmd[256];
	sprintf(szCmd,"bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;secammo;primammo;vesthelm;defuser",szFavWpn[5][0],szFavWpn[5][1],szFavWpn[5][2],szFavWpn[5][3]);
	pBuyMenuButtonBuy->SetCommand(szCmd);

	pBuyMenuButtonBuy->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_BUY"));
	pBuyMenuButtonBuy->SetKey('b');
	memcpy(pBuyMenuButtonBuy->iTga3,g_UI_Button_Glow,sizeof(g_UI_Button_Glow));
	pBuyMenuButtonBuy->m_iSize = 14;
	pBuyMenuButtonBuy->m_Tex_Type = MGUI_TEX_TYPE_3;
	pBuyMenuButtonBuy->m_iOffset[0] = 2;

	pBuyMenuButtonClose = MGUI_CreateButton(pBuyMenuPanel,0,0,0,0);
	pBuyMenuButtonClose->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
	pBuyMenuButtonClose->SetCommand("");
	pBuyMenuButtonClose->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_QUIT"));
	memcpy(pBuyMenuButtonClose->iTga3,g_UI_Button,sizeof(g_UI_Button));
	pBuyMenuButtonClose->m_iSize = 14;
	pBuyMenuButtonClose->m_Tex_Type = MGUI_TEX_TYPE_3;


	pBuyMenuImageSlot = MGUI_CreateImage(pBuyMenuPanel,0 ,0, 0, 0, true, false);
	pBuyMenuImageSlot->SetTexture("gfx\\ui\\panel\\blank_slot");
	for(int i=0;i<=1;i++)
	{
		pBuyMenuButtonSlot[i] = MGUI_CreateButton(pBuyMenuPanel,0,0,0,0);
		pBuyMenuButtonSlot[i]->SetType(MGUI_BUTTON_TYPE_COMMAND);	
	}
	pBuyMenuButtonSlot[0]->SetCommand("MGUI.TeamSuitPrevSlot");
	pBuyMenuButtonSlot[1]->SetCommand("MGUI.TeamSuitNextSlot");
	pBuyMenuButtonSlot[0]->SetImage("gfx\\ui\\page\\btn_page_prev@n","gfx\\ui\\page\\btn_page_prev@o","gfx\\ui\\page\\btn_page_prev@c");
	pBuyMenuButtonSlot[1]->SetImage("gfx\\ui\\page\\btn_page_next@n","gfx\\ui\\page\\btn_page_next@o","gfx\\ui\\page\\btn_page_next@c");

	pBuyMenuLabelSlot = MGUI_CreateLabel(pBuyMenuPanel, 0, 0, 0, 0);
	pBuyMenuLabelSlot->SetSize(14);
	pBuyMenuLabelSlot->SetColor(255,251,219,255);
	pBuyMenuLabelSlot->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_SUIT1"));
	pBuyMenuLabelSlot->m_iAlignment = 2;

}
void BTEPanel_BuyMenu_Reset()
{
	bFirst = true;
	iTDMSlot = 0;
	pBuyMenuLabelSlot->SetLabel(GetLangUni("CSBTE_TEAMSUITPANEL_SUIT1"));
	for(int i=0;i<=9;i++)
	{
		pBuyMenuButton[i]->m_fNextClick = 0.0f;
	}
	for(int i=0;i<=1;i++)
	{
		pBuyMenuButtonPage[i]->m_fNextClick = 0.0f;
		pBuyMenuButton2[i]->m_fNextClick = 0.0f;
		pBuyMenuButtonSlot[i]->m_fNextClick = 0.0f;
	}
	for(int i=0;i<=4;i++)
	{
		pBuyMenuButtonFav[i]->m_fNextClick = 0.0f;
	}		
	pBuyMenuButtonBuy->m_fNextClick = 0.0f;
	pBuyMenuButtonClose->m_fNextClick = 0.0f;

}
void BTEPanel_BuyMenu_UpdateItems(int iSlot, char *pItems)
{
	if(bFirst)	BTEPanel_BuyMenu_First();

	pBuyMenuPanel->m_iClosing = 0;
	pTeamSuitPanel->m_iClosing = 1;
	for(int i=0;i<=9;i++)pBuyMenuPanel_WpnInfo[i]->m_iClosing = 1;
	int iLocal =gEngfuncs.GetLocalPlayer()->index;

	float scale = (float)g_sScreenInfo.iHeight / 480;
	pBuyMenuButton2[1]->SetType(MGUI_BUTTON_TYPE_COMMAND);
	if(iSlot == -1)
	{	

		if(vPlayer[iLocal].team==1)	pBuyMenuButton2[1]->SetCommand("bte_buy_wpn m4a1;bte_buy_wpn usp;bte_buy_wpn hegrenade;bte_buy_wpn knife;secammo;primammo;vesthelm;defuser");
		else	pBuyMenuButton2[1]->SetCommand("bte_buy_wpn ak47;bte_buy_wpn usp;bte_buy_wpn hegrenade;bte_buy_wpn knife;secammo;primammo;vesthelm");

		for(int i=0;i<=1;i++)
		{
			pBuyMenuButtonPage[i]->SetVisible(false);
		}

		for(int i=0;i<=9;i++)
		{
			
			pBuyMenuLabel[i]->SetLabel(GetLangUni(MENU[i]));
			pBuyMenuLabel[i]->SetVisible(true);
	
			char szCmd[32];
			sprintf(szCmd,CMD[i],0);
			pBuyMenuButton[i]->SetCommand(szCmd);
			pBuyMenuButton[i]->SetType(MGUI_BUTTON_TYPE_COMMAND);
			pBuyMenuButton[i]->SetEnabled(true);
			pBuyMenuButton[i]->SetVisible(true);
			pBuyMenuButton[i]->m_OverPanel = 0;	
	
			pBuyMenuLabelKey[i]->SetVisible(true);
			pBuyMenuLabelKey[i]->SetColor(255,255,255,255);
			pBuyMenuImage[i]->SetVisible(true);
			pBuyMenuImageWpn[i]->SetVisible(false);
			
			if(vPlayer[iLocal].team==1)
				pBuyMenuLabel[i]->SetColor(192,205,224,255);
			else
				pBuyMenuLabel[i]->SetColor(216,182,183,255);
		}

		switch (g_iWeaponLimit)
		{
			case 1:
			{
				for(int i=0;i<=9;i++)
				{
					pBuyMenuButton[i]->SetEnabled(false);
					//pBuyMenuLabel[i]->SetColor(90,90,90,255);
					//pBuyMenuLabelKey[i]->SetColor(150,150,150,255);
				}

				if(vPlayer[iLocal].team==1)
				{
					pBuyMenuLabel[3]->SetColor(192,205,224,255);
					pBuyMenuLabel[8]->SetColor(192,205,224,255);
				}
				else
				{
					pBuyMenuLabel[3]->SetColor(216,182,183,255);
					pBuyMenuLabel[8]->SetColor(216,182,183,255);
				}

				pBuyMenuLabelKey[3]->SetColor(255,255,255,255);
				pBuyMenuLabelKey[8]->SetColor(255,255,255,255);
				pBuyMenuButton[3]->SetEnabled(true);
				pBuyMenuButton[8]->SetEnabled(true);
				break;
			}
			case 2:
			{
				for(int i=0;i<=9;i++)
				{
					pBuyMenuButton[i]->SetEnabled(false);
					/*pBuyMenuLabel[i]->SetColor(90,90,90,255);
					pBuyMenuLabelKey[i]->SetColor(150,150,150,255);*/
				}

				if(vPlayer[iLocal].team==1)
				{
					pBuyMenuLabel[0]->SetColor(192,205,224,255);
					pBuyMenuLabel[8]->SetColor(192,205,224,255);
				}
				else
				{
					pBuyMenuLabel[0]->SetColor(216,182,183,255);
					pBuyMenuLabel[8]->SetColor(216,182,183,255);
				}

				pBuyMenuLabelKey[0]->SetColor(255,255,255,255);
				pBuyMenuLabelKey[8]->SetColor(255,255,255,255);
				pBuyMenuButton[0]->SetEnabled(true);
				pBuyMenuButton[8]->SetEnabled(true);
				break;
				break;
			}
			case 3:
			{
				for(int i=0;i<=9;i++)
				{
					pBuyMenuButton[i]->SetEnabled(false);
					/*pBuyMenuLabel[i]->SetColor(90,90,90,255);
					pBuyMenuLabelKey[i]->SetColor(150,150,150,255);*/
				}

				if(vPlayer[iLocal].team==1)
				{
					pBuyMenuLabel[7]->SetColor(192,205,224,255);
					pBuyMenuLabel[8]->SetColor(192,205,224,255);
				}
				else
				{
					pBuyMenuLabel[7]->SetColor(216,182,183,255);
					pBuyMenuLabel[8]->SetColor(216,182,183,255);
				}

				pBuyMenuLabelKey[7]->SetColor(255,255,255,255);
				pBuyMenuLabelKey[8]->SetColor(255,255,255,255);
				pBuyMenuButton[7]->SetEnabled(true);
				pBuyMenuButton[8]->SetEnabled(true);
				break;
			}
			case 4:
			{
				for(int i=0;i<=9;i++)
				{
					pBuyMenuButton[i]->SetEnabled(false);
					/*pBuyMenuLabel[i]->SetColor(90,90,90,255);
					pBuyMenuLabelKey[i]->SetColor(150,150,150,255);*/
				}

				if(vPlayer[iLocal].team==1)
				{
					pBuyMenuLabel[8]->SetColor(192,205,224,255);
				}
				else
				{
					pBuyMenuLabel[8]->SetColor(216,182,183,255);
				}

				pBuyMenuLabelKey[8]->SetColor(255,255,255,255);
				pBuyMenuButton[8]->SetEnabled(true);
				break;
			}
		}


		pBuyMenuButton[5]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
		pBuyMenuButton[6]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
		pBuyMenuButton[9]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);

		if(g_iMod != MOD_NONE && g_iMod != MOD_ZBS && g_iMod != MOD_FUNMODE)
		{
			pBuyMenuButton[5]->SetEnabled(false);
			pBuyMenuButton[6]->SetEnabled(false);
			/*pBuyMenuLabelKey[5]->SetVisible(false);
			pBuyMenuLabelKey[6]->SetVisible(false);*/
			/*pBuyMenuImage[5]->SetVisible(false);
			pBuyMenuImage[6]->SetVisible(false);*/
			pBuyMenuLabel[5]->SetVisible(false);
			pBuyMenuLabel[6]->SetVisible(false);			
		}
		else
		{
			pBuyMenuButton[5]->SetEnabled(true);
			pBuyMenuButton[6]->SetEnabled(true);
			pBuyMenuButton[7]->SetEnabled(true);
			pBuyMenuButton[9]->SetEnabled(true);
			pBuyMenuButtonClose->SetEnabled(true);
		}

		if(g_iMod == MOD_TDM || g_iMod == MOD_DM || g_iMod == MOD_BC || g_iMod == MOD_HD || g_iMod == MOD_SD || g_iMod == MOD_ZB4)
		{
			pBuyMenuButton[9]->SetEnabled(false);
			pBuyMenuButtonClose->SetEnabled(false);
		}
	}
	else
	{
		if(iSlot != 9)
		{
			if(vPlayer[iLocal].team==1)
				pBuyMenuLabel[iSlot]->SetColor(192,205,224,255);
			else
				pBuyMenuLabel[iSlot]->SetColor(216,182,183,255);			

			if(pItems[0] != '\0')
			{
				char szCmd[64];
				if(g_iMod == MOD_NONE || g_iMod == MOD_ZBS || g_iMod == MOD_FUNMODE)
				{
					pBuyMenuButton[iSlot]->SetType(MGUI_BUTTON_TYPE_CLOSEALL);
					if(!strcmp(pItems,"vest") || !strcmp(pItems,"vesthelm") || !strcmp(pItems,"flash") || !strcmp(pItems,"sgren") || !strcmp(pItems,"defuser") || !strcmp(pItems,"nvgs"))
						sprintf(szCmd,"%s",pItems);
					else
						sprintf(szCmd,"bte_buy_wpn %s",pItems);
				}
				else
				{
					pBuyMenuButton[iSlot]->SetType(MGUI_BUTTON_TYPE_COMMAND);
					if(!strcmp(pItems,"vest") || !strcmp(pItems,"vesthelm") || !strcmp(pItems,"flash") || !strcmp(pItems,"sgren") || !strcmp(pItems,"defuser") || !strcmp(pItems,"nvgs"))
						sprintf(szCmd,"");
					else
						sprintf(szCmd,"bte_select_wpn %s",pItems);					
				}
				char szTga[64];
				sprintf(szTga,"gfx\\vgui\\%s",pItems);
				pBuyMenuImageWpn[iSlot]->SetTexture(szTga);
				pBuyMenuImageWpn[iSlot]->SetVisible(true);
				char szName[64];
				sprintf(szName,"CSBTE_%s",pItems);
				pBuyMenuLabel[iSlot]->SetLabel(GetLangUni(szName));
				
				pBuyMenuButton[iSlot]->SetCommand(szCmd);
				pBuyMenuButton[iSlot]->SetEnabled(true);
				pBuyMenuButton[iSlot]->SetVisible(true);
				pBuyMenuLabelKey[iSlot]->SetVisible(true);
				pBuyMenuLabel[iSlot]->SetVisible(true);
				pBuyMenuPanelImage_WpnInfo[iSlot][1]->SetTexture(szTga);
				pBuyMenuButton[iSlot]->m_OverPanel = pBuyMenuPanel_WpnInfo[iSlot];
				pBuyMenuImage[iSlot]->SetVisible(true);				
				


				char value[1024], str[1024];
				GetPrivateProfileStringA(strupr(pItems),WEAPON_INFO_INI[0],"Null",value,sizeof(value),configPath);
				if(strstr(value,"Null"))
				{
					for(int j=0;j<=6;j++)
					{
						pBuyMenuPanelImage_WpnInfo_Line[iSlot][j]->SetVisible(false);
						pBuyMenuPanelLabel_WpnInfo[iSlot][j][0]->SetVisible(false);
						pBuyMenuPanelLabel_WpnInfo[iSlot][j][1]->SetVisible(false);
					}
					pBuyMenuPanelLabel_WpnInfo[iSlot][0][0]->SetVisible(true);					
					pBuyMenuPanelLabel_WpnInfo[iSlot][0][1]->SetVisible(true);

					pBuyMenuPanelLabel_WpnInfo[iSlot][1][0]->SetVisible(true);
					pBuyMenuPanelLabel_WpnInfo[iSlot][1][1]->SetVisible(true);

					char szName[64];
					sprintf(szName,"CSBTE_%s_Desc",pItems);
					//GetPrivateProfileStringA(strupr(pItems),"Description","Null",value,sizeof(value),configPath);
					pBuyMenuPanelLabel_WpnInfo[iSlot][0][1]->SetLabel(GetLangUni(szName));
		
					pBuyMenuPanelLabel_WpnInfo[iSlot][0][0]->SetLabel(GetLangUni("CSBTE_BUYMENU_WEAPONINFO_DESC"));
					pBuyMenuPanelLabel_WpnInfo[iSlot][1][0]->SetLabel(GetLangUni("CSBTE_BUYMENU_WEAPONINFO_COST"));
					
					pBuyMenuPanelLabel_WpnInfo[iSlot][0][1]->x =  pBuyMenuPanelLabel_WpnInfo[iSlot][0][0]->x + 28 + 1 + int(5 * scale);
					pBuyMenuPanelLabel_WpnInfo[iSlot][1][1]->x =  pBuyMenuPanelLabel_WpnInfo[iSlot][0][0]->x + 28 + 1 + int(5 * scale);

					int iH = Fonts_GetHeight(pBuyMenuPanelLabel_WpnInfo[iSlot][0][1]->pszLabel, pBuyMenuPanelLabel_WpnInfo[iSlot][0][1]->w , 3);
					int iOffset = pBuyMenuPanelImage_WpnInfo[iSlot][1]->y;
					pBuyMenuPanelLabel_WpnInfo[iSlot][1][0]->y = iOffset*2 + (int)((pBuyMenuPanelImage_WpnInfo[1][1]->h) + 1 * (2.5 * scale + 14)) + iH + 5 * scale;
					pBuyMenuPanelLabel_WpnInfo[iSlot][1][1]->y = iOffset*2 + (int)((pBuyMenuPanelImage_WpnInfo[1][1]->h) + 1 * (2.5 * scale + 14)) + iH + 5 * scale;
					
					GetPrivateProfileStringA(strupr(pItems),WEAPON_INFO_INI[5],"0",value,sizeof(value),configPath);
					if(!strcmp(value,"0"))
					{
						pBuyMenuPanelLabel_WpnInfo[iSlot][1][0]->SetVisible(false);
						pBuyMenuPanelLabel_WpnInfo[iSlot][1][1]->SetVisible(false);
					}
					else
					{
						if(g_iMoney<atoi(value) && (g_iMod == MOD_NONE || g_iMod == MOD_ZBS || g_iMod == MOD_FUNMODE))
						{
							pBuyMenuLabel[iSlot]->SetColor(90,90,90,255);
							pBuyMenuButton[iSlot]->SetType(MGUI_BUTTON_TYPE_COMMAND);
							pBuyMenuButton[iSlot]->SetCommand("");
						}
						else
							if(vPlayer[iLocal].team==1)
								pBuyMenuLabel[iSlot]->SetColor(192,205,224,255);
							else
								pBuyMenuLabel[iSlot]->SetColor(216,182,183,255);
						
						sprintf(str,"$%s",value);
						pBuyMenuPanelLabel_WpnInfo[iSlot][1][1]->SetLabel(UTF8ToUnicode(str));
					}



				}
				else
				{
					int iOffset = pBuyMenuPanelImage_WpnInfo[iSlot][1]->y;
					pBuyMenuPanelLabel_WpnInfo[iSlot][1][0]->y = iOffset*2 + (int)((pBuyMenuPanelImage_WpnInfo[1][1]->h) + 1 * (2.5 * scale + 14));
					pBuyMenuPanelLabel_WpnInfo[iSlot][1][1]->y = iOffset*2 + (int)((pBuyMenuPanelImage_WpnInfo[1][1]->h) + 1 * (2.5 * scale + 14));

					for(int j=0;j<=6;j++)
					{
						pBuyMenuPanelImage_WpnInfo_Line[iSlot][j]->SetVisible(true);
						pBuyMenuPanelLabel_WpnInfo[iSlot][j][0]->SetVisible(true);
						pBuyMenuPanelLabel_WpnInfo[iSlot][j][1]->SetVisible(true);
						pBuyMenuPanelLabel_WpnInfo[iSlot][j][0]->SetLabel(GetLangUni(WEAPON_INFO[j]));
					}
					for(int j=0;j<=4;j++)
					{
						pBuyMenuPanelLabel_WpnInfo[iSlot][j][1]->x = int(102 * scale);

						GetPrivateProfileStringA(strupr(pItems),WEAPON_INFO_INI[j],"0",value,sizeof(value),configPath);
						pBuyMenuPanelImage_WpnInfo_Line[iSlot][j]->w = int(atoi(value) / 1.6 * scale);			
						
						sprintf(str,"%s%%",value);
						pBuyMenuPanelLabel_WpnInfo[iSlot][j][1]->SetLabel(UTF8ToUnicode(str));
					}
					//for(int j=5;j<=6;j++)
					//{
					GetPrivateProfileStringA(strupr(pItems),WEAPON_INFO_INI[5],"0",value,sizeof(value),configPath);
					if(g_iMoney<atoi(value) && (g_iMod == MOD_NONE || g_iMod == MOD_ZBS || g_iMod == MOD_FUNMODE))
					{
						pBuyMenuLabel[iSlot]->SetColor(90,90,90,255);
						pBuyMenuButton[iSlot]->SetType(MGUI_BUTTON_TYPE_COMMAND);
						pBuyMenuButton[iSlot]->SetCommand("");
					}
					else
						if(vPlayer[iLocal].team==1)
							pBuyMenuLabel[iSlot]->SetColor(192,205,224,255);
						else
							pBuyMenuLabel[iSlot]->SetColor(216,182,183,255);
					
					sprintf(str,"$%s",value);
					pBuyMenuPanelLabel_WpnInfo[iSlot][5][1]->SetLabel(UTF8ToUnicode(str));
						
					GetPrivateProfileStringA(strupr(pItems),WEAPON_INFO_INI[6],"0",value,sizeof(value),configPath);
					pBuyMenuPanelLabel_WpnInfo[iSlot][6][1]->SetLabel(UTF8ToUnicode(value));
				}
			}
			else
			{
				pBuyMenuImageWpn[iSlot]->SetVisible(false);
				pBuyMenuImage[iSlot]->SetVisible(false);
				pBuyMenuButton[iSlot]->SetVisible(false);
				pBuyMenuButton[iSlot]->SetType(MGUI_BUTTON_TYPE_COMMAND);
				pBuyMenuLabel[iSlot]->SetVisible(false);
				pBuyMenuLabelKey[iSlot]->SetVisible(false);
				pBuyMenuButton[iSlot]->m_OverPanel = 0;
			}
		}
		else
		{
			pBuyMenuLabel[iSlot]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_BACK"));
			pBuyMenuButton[iSlot]->SetEnabled(true);			
			pBuyMenuButton[iSlot]->SetCommand("MGUI.ShowBuyMenu");
			pBuyMenuButton[iSlot]->SetType(MGUI_BUTTON_TYPE_COMMAND);
		}
	}
}

void BTEPanel_BuyMenu_SetHaveNextPage(int iHavePrevPage,int iHaveNextPage)
{
	char szCmd[32];
	if(iHavePrevPage)
	{		
		sprintf(szCmd,"bte_wpn_menu_gui %d %d",iType,iPage - 1);
		pBuyMenuButtonPage[0]->SetCommand(szCmd);		
		pBuyMenuButtonPage[0]->SetEnabled(true);
	}
	else pBuyMenuButtonPage[0]->SetEnabled(false);
	if(iHaveNextPage)
	{		
		sprintf(szCmd,"bte_wpn_menu_gui %d %d",iType,iPage + 1);
		pBuyMenuButtonPage[1]->SetCommand(szCmd);		
		pBuyMenuButtonPage[1]->SetEnabled(true);
	}
	else pBuyMenuButtonPage[1]->SetEnabled(false);
	pBuyMenuButtonPage[0]->SetVisible(true);
	pBuyMenuButtonPage[1]->SetVisible(true);
}

void BTEPanel_BuyMenu_SetPage(int page,int type)
{
	iPage = page;
	iType = type;
}

void BTEPanel_BuyMenu_Close()
{
	pBuyMenuPanel->m_iClosing = 1;
	g_mgui_candraw = 0;
}
void BTEPanel_BuyMenu_First()
{
	bFirst = false;
	float scale = (float)g_sScreenInfo.iHeight / 480;

	pBuyMenuPanel->x = (int)((g_sScreenInfo.iWidth - 606 * scale) / 2);
	pBuyMenuPanel->prevx = pBuyMenuPanel->x;
	pBuyMenuPanel->y = (int)((g_sScreenInfo.iHeight - 420 * scale) /2);
	pBuyMenuPanel->prevy = pBuyMenuPanel->y;
	pBuyMenuPanel->w = (int)(606 * scale);
	pBuyMenuPanel->h = (int)(420 * scale);

	int iLocal =gEngfuncs.GetLocalPlayer()->index;
	for(int i=0;i<=9;i++)
	{
		pBuyMenuPanel_WpnInfo[i]->x = pBuyMenuPanel->x + int(231 * scale);
		pBuyMenuPanel_WpnInfo[i]->prevx = pBuyMenuPanel_WpnInfo[i]->x;
		pBuyMenuPanel_WpnInfo[i]->y = pBuyMenuPanel->y + int(48 * scale);
		pBuyMenuPanel_WpnInfo[i]->prevy = pBuyMenuPanel_WpnInfo[i]->y;
		pBuyMenuPanel_WpnInfo[i]->w = (int)(146 * scale);
		pBuyMenuPanel_WpnInfo[i]->h = (int)(188 * scale);

		for(int j=0;j<=1;j++)
		{
			pBuyMenuPanelImage_WpnInfo[i][j]->x = 0;
			pBuyMenuPanelImage_WpnInfo[i][j]->y = 0;
			pBuyMenuPanelImage_WpnInfo[i][j]->w = (int)(146.875 * scale);
			pBuyMenuPanelImage_WpnInfo[i][j]->h = (int)(50.625 * scale);
		}
		int iOffset = 20;
		
		pBuyMenuPanelImage_WpnInfo[i][0]->h = (int)(175 * scale);
		pBuyMenuPanelImage_WpnInfo[i][1]->y = (int)(iOffset * scale) - iOffset;

		iOffset = pBuyMenuPanelImage_WpnInfo[i][1]->y;

		for(int j=0;j<=4;j++)
		{
			for(int k=0;k<=1;k++)
			{
				pBuyMenuPanelLabel_WpnInfo[i][j][k]->w = (int)(146 * scale);
				pBuyMenuPanelLabel_WpnInfo[i][j][k]->y = iOffset*2 + (int)((pBuyMenuPanelImage_WpnInfo[i][1]->h) + j * (2.5 * scale + 14));
			}
			pBuyMenuPanelLabel_WpnInfo[i][j][0]->x = int(12.5 * scale);
			pBuyMenuPanelLabel_WpnInfo[i][j][1]->x = int(102 * scale);
			pBuyMenuPanelLabel_WpnInfo[i][j][1]->w = 93 * scale;

			pBuyMenuPanelImage_WpnInfo_Line[i][j]->x = 1 + pBuyMenuPanelLabel_WpnInfo[i][j][0]->x + 28 + (pBuyMenuPanelLabel_WpnInfo[i][j][1]->x - (pBuyMenuPanelLabel_WpnInfo[i][j][0]->x + 28) - 62.5 * scale) / 2;
			pBuyMenuPanelImage_WpnInfo_Line[i][j]->y = pBuyMenuPanelLabel_WpnInfo[i][j][0]->y + 5;
			pBuyMenuPanelImage_WpnInfo_Line[i][j]->h = 8;
		}
		for(int j=5;j<=6;j++)
		{
			for(int k=0;k<=1;k++)
			{					
				pBuyMenuPanelLabel_WpnInfo[i][j][k]->w = (int)(146 * scale);
				pBuyMenuPanelLabel_WpnInfo[i][j][k]->y = iOffset*2*scale + (int)((pBuyMenuPanelImage_WpnInfo[i][1]->h+4) + j * (2.5 * scale + 14));
			}
			pBuyMenuPanelLabel_WpnInfo[i][j][0]->x = int(12.5 * scale);
			pBuyMenuPanelLabel_WpnInfo[i][j][1]->x = pBuyMenuPanelLabel_WpnInfo[i][j][0]->x + 28 + 1 + int(3 * scale);
		}

		pBuyMenuLabel[i]->x = int(38 * scale);
		pBuyMenuLabel[i]->y = int(48 * scale) + int(i * 25 * scale);
		pBuyMenuLabel[i]->h = int(24.375 * scale);
		/*pBuyMenuLabel[i]->SetLabel(GetLangUni(MENU[i]));
		pBuyMenuLabel[i]->SetVisible(true);*/
		if(vPlayer[iLocal].team==1)
			pBuyMenuLabel[i]->SetColor(192,205,224,255);
		else
			pBuyMenuLabel[i]->SetColor(216,182,183,255);

		pBuyMenuButton[i]->x = int(13.75 * scale);
		pBuyMenuButton[i]->y = int(48 * scale) + int(i * 25 * scale);
		pBuyMenuButton[i]->w = int(203 * scale);
		pBuyMenuButton[i]->h = int(24.375 * scale);
		//pBuyMenuButton[i]->m_fNextClick = g_flTime + 0.2f;
		/*char szCmd[32];
		sprintf(szCmd,CMD[i],0);
		pBuyMenuButton[i]->SetCommand(szCmd);
		pBuyMenuButton[i]->SetType(MGUI_BUTTON_TYPE_COMMAND);
		pBuyMenuButton[i]->SetEnabled(true);
		pBuyMenuButton[i]->SetVisible(true);
		pBuyMenuButton[i]->m_OverPanel = 0;*/

		pBuyMenuLabelKey[i]->x = int(23 * scale);
		pBuyMenuLabelKey[i]->y = int(48 * scale) + int(i * 25 * scale);
		pBuyMenuLabelKey[i]->w = int(203 * scale);
		pBuyMenuLabelKey[i]->h = int(24.375 * scale);
		//pBuyMenuLabelKey[i]->SetVisible(true);

		pBuyMenuImage[i]->x = int(16 * scale);
		pBuyMenuImage[i]->y = int(51 * scale) + int(i * 25 * scale);
		pBuyMenuImage[i]->h = int(19 * scale);
		pBuyMenuImage[i]->w = pBuyMenuImage[i]->h;
		//pBuyMenuImage[i]->SetVisible(true);
		
		pBuyMenuImageWpn[i]->y = pBuyMenuButton[i]->y;
		pBuyMenuImageWpn[i]->h = pBuyMenuButton[i]->h;
		pBuyMenuImageWpn[i]->w = int(pBuyMenuImageWpn[i]->h * 2.9);
		pBuyMenuImageWpn[i]->m_iTexture = -1;
		pBuyMenuImageWpn[i]->x = pBuyMenuButton[i]->x + pBuyMenuButton[i]->w - pBuyMenuImageWpn[i]->w;
	}
	for(int i=0;i<=1;i++)
	{
		pBuyMenuButtonPage[i]->y = int(48 * scale) + int(255 * scale);
		pBuyMenuButtonPage[i]->w = int(65.25 * scale);
		pBuyMenuButtonPage[i]->h = int(20 * scale);


		pBuyMenuButton2[i]->x = pBuyMenuButton[i]->x + pBuyMenuButton[i]->w + 22 * scale;
		pBuyMenuButton2[i]->y = pBuyMenuButton[8]->y - 3 * scale + i * 29 * scale;
		pBuyMenuButton2[i]->w = int(132 * scale);
		pBuyMenuButton2[i]->h = int(25 * scale);

		pBuyMenuPanelImageTimer[i]->x = 432 * scale;
		pBuyMenuPanelImageTimer[i]->y = 271 * scale + i * 21 * scale;
		pBuyMenuPanelImageTimer[i]->w = 140 * scale;
		pBuyMenuPanelImageTimer[i]->h = 16 * scale;

		pBuyMenuPanelLabelTimer[i]->x = pBuyMenuPanelImageTimer[i]->x + 3;
		pBuyMenuPanelLabelTimer[i]->y = pBuyMenuPanelImageTimer[i]->y  - 2;
		pBuyMenuPanelLabelTimer[i]->w = 134 * scale;
		pBuyMenuPanelLabelTimer[i]->h = 16 * scale;
		
		pBuyMenuPanelLabelTimer2[i]->x = pBuyMenuPanelImageTimer[i]->x + 3;
		pBuyMenuPanelLabelTimer2[i]->y = pBuyMenuPanelImageTimer[i]->y  - 2;
		pBuyMenuPanelLabelTimer2[i]->w = 134 * scale;
		pBuyMenuPanelLabelTimer2[i]->h = 16 * scale;
	}
	//pBuyMenuButtonPage[0]->x = int(13.75 * scale);
	pBuyMenuButtonPage[1]->x = pBuyMenuButton[0]->x + pBuyMenuButton[0]->w - pBuyMenuButtonPage[1]->w;
	pBuyMenuButtonPage[0]->x = pBuyMenuButtonPage[1]->x - pBuyMenuButtonPage[1]->w - int(3 * scale);

	/*pBuyMenuButton2[1]->x = pBuyMenuButton[0]->x + pBuyMenuButton[0]->w - pBuyMenuButtonPage[1]->w;
	pBuyMenuButton2[0]->x = pBuyMenuButtonPage[1]->x - pBuyMenuButtonPage[1]->w - int(3 * scale);*/

	for(int i=0;i<=4;i++)
	{
		/*pBuyMenuImageFavBg[i]->x = pBuyMenuButton[i]->x + pBuyMenuButton[i]->w + pBuyMenuPanel_WpnInfo[0]->w + 32 * scale;
		pBuyMenuImageFavBg[i]->y = int(48 * scale) + int(i * 40 * scale);
		pBuyMenuImageFavBg[i]->w = int(175 * scale);
		pBuyMenuImageFavBg[i]->h = int(37.5 * scale);*/

		/*pBuyMenuImageFav[i]->x = pBuyMenuButton[i]->x + pBuyMenuButton[i]->w + pBuyMenuPanel_WpnInfo[0]->w + 32 * scale;
		pBuyMenuImageFav[i]->y = int(48 * scale) + int(i * 40 * scale);
		pBuyMenuImageFav[i]->w = int(175 * scale);
		pBuyMenuImageFav[i]->h = int(37.5 * scale);*/
		//pBuyMenuImageFav[i]->SetTexture("other\\ui\\panel\\favoritebg");
		
		pBuyMenuButtonFav[i]->x = pBuyMenuButton[i]->x + pBuyMenuButton[i]->w + pBuyMenuPanel_WpnInfo[0]->w + 32 * scale;
		pBuyMenuButtonFav[i]->y = int(48 * scale) + int(i * 40 * scale);
		pBuyMenuButtonFav[i]->w = int(175 * scale);
		pBuyMenuButtonFav[i]->h = int(37.5 * scale);
		pBuyMenuButtonFav[i]->iTga[1] = pBuyMenuButtonFav[i]->iTga[2] = FindTexture("gfx\\ui\\panel\\select");
 		//pBuyMenuButtonFav[i]->SetImage("gfx\\ui\\panel\\favoritebg","gfx\\ui\\panel\\select","gfx\\ui\\panel\\select");
		//pBuyMenuButtonFav[i]->iTga[1] = pBuyMenuButtonFav[i]->iTga[2] = DrawTgaGetID("gfx\\ui\\panel\\select");
		
		pBuyMenuImageFavKey[i]->x = pBuyMenuButtonFav[i]->x + 2 * scale;
		pBuyMenuImageFavKey[i]->w = int(20 * scale);
		pBuyMenuImageFavKey[i]->h = pBuyMenuImageFavKey[i]->w;
		pBuyMenuImageFavKey[i]->y = pBuyMenuButtonFav[i]->y + pBuyMenuButtonFav[i]->h / 2 - pBuyMenuImageFavKey[i]->h / 2;
		
		pBuyMenuLabelFavKey[i]->x = pBuyMenuButtonFav[i]->x + pBuyMenuImageFavKey[i]->w / 2 - 1;// - /*Fonts_GetLen(pBuyMenuLabelFavKey[i]->pszLabel)*/7 / 2 - 1;
		pBuyMenuLabelFavKey[i]->y = pBuyMenuImageFavKey[i]->y + pBuyMenuImageFavKey[i]->h / 2 + pBuyMenuLabelFavKey[i]->m_iSize / 2;
		pBuyMenuLabelFavKey[i]->w = pBuyMenuButtonFav[i]->m_iSize;
		pBuyMenuLabelFavKey[i]->h = pBuyMenuButtonFav[i]->m_iSize;

		for(int j=0;j<=2;j++)
		{
			pBuyMenuImageFavWpn[i][j]->x = pBuyMenuButtonFav[i]->x + 22 * scale;
			pBuyMenuImageFavWpn[i][j]->y = pBuyMenuButtonFav[i]->y + 1 * scale;
			pBuyMenuImageFavWpn[i][j]->h = pBuyMenuButtonFav[i]->h * 0.95;
			pBuyMenuImageFavWpn[i][j]->w = pBuyMenuImageFavWpn[i][j]->h * 2.9;
		}
		

		pBuyMenuImageFavWpn[i][1]->h = pBuyMenuImageFavWpn[i][2]->h = pBuyMenuImageFavWpn[i][0]->h * 0.5;
		pBuyMenuImageFavWpn[i][1]->w = pBuyMenuImageFavWpn[i][2]->w = pBuyMenuImageFavWpn[i][0]->w * 0.5;

		pBuyMenuImageFavWpn[i][2]->y = pBuyMenuImageFavWpn[i][0]->y + pBuyMenuImageFavWpn[i][0]->h / 2;

		pBuyMenuImageFavWpn[i][1]->x = pBuyMenuImageFavWpn[i][2]->x = pBuyMenuImageFavWpn[i][0]->x + pBuyMenuImageFavWpn[i][0]->w - 5 * scale;
		pBuyMenuImageFavWpn[i][1]->y += 2 * scale;
	}

	for(int i=0;i<=1;i++)
	{
		for(int j=0;j<=4;j++)
		{
			pBuyMenuImageQuickBuy[i][j]->x = pBuyMenuButton[i]->x;
			pBuyMenuImageQuickBuy[i][j]->y = 330 * scale;
			pBuyMenuImageQuickBuy[i][j]->w = 146.875 * scale;
			pBuyMenuImageQuickBuy[i][j]->h = 50.625 * scale;
		}
	}
	
	pBuyMenuImageQuickBuy[0][1]->x += pBuyMenuImageQuickBuy[0][0]->w + 2 * scale;
	pBuyMenuImageQuickBuy[0][1]->w = 108.125 * scale;
	pBuyMenuImageQuickBuy[1][1]->x -= 14 * scale - pBuyMenuImageQuickBuy[0][1]->x;	
	pBuyMenuImageQuickBuy[0][2]->x = pBuyMenuImageQuickBuy[0][1]->x + pBuyMenuImageQuickBuy[0][1]->w + 2 * scale;
	pBuyMenuImageQuickBuy[0][2]->w = 60 * scale;
	pBuyMenuImageQuickBuy[1][2]->x = pBuyMenuImageQuickBuy[0][2]->x - 42 * scale;
	pBuyMenuImageQuickBuy[0][3]->x = pBuyMenuImageQuickBuy[0][2]->x + pBuyMenuImageQuickBuy[0][2]->w + 2 * scale;
	pBuyMenuImageQuickBuy[0][3]->w = 156 * scale;
	pBuyMenuImageQuickBuy[1][3]->x = pBuyMenuImageQuickBuy[0][3]->x + 36 * scale;
	pBuyMenuImageQuickBuy[0][4]->x = pBuyMenuImageQuickBuy[0][3]->x + pBuyMenuImageQuickBuy[0][3]->w + 2 * scale;
	pBuyMenuImageQuickBuy[0][4]->w = 80 * scale;
	pBuyMenuImageQuickBuy[1][4]->x = pBuyMenuImageQuickBuy[0][4]->x - 3 * scale;
	pBuyMenuImageQuickBuy[1][4]->y += 10 * scale;

	pBuyMenuImageQuickBuy[1][4]->w = pBuyMenuImageQuickBuy[1][0]->w * 0.6;
	pBuyMenuImageQuickBuy[1][4]->h = pBuyMenuImageQuickBuy[1][0]->h * 0.6;	

	pBuyMenuImageQuickBuy[1][2]->w = pBuyMenuImageQuickBuy[1][0]->w * 0.75;
	pBuyMenuImageQuickBuy[1][2]->h = pBuyMenuImageQuickBuy[1][0]->h * 0.75;
	pBuyMenuImageQuickBuy[1][2]->x += 19 * scale;
	pBuyMenuImageQuickBuy[1][2]->y += 5 * scale;

	pBuyMenuImageQuickBuy[1][1]->w = pBuyMenuImageQuickBuy[1][0]->w * 0.75;
	pBuyMenuImageQuickBuy[1][1]->h = pBuyMenuImageQuickBuy[1][0]->h * 0.75;
	pBuyMenuImageQuickBuy[1][1]->y += 5 * scale;

	/*pBuyMenuButton2[0]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_REBUY"));
	pBuyMenuButton2[1]->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_AUTOBUY"));*/


	pBuyMenuButtonBuy->x = 420 * scale;
	pBuyMenuButtonBuy->y = 385 * scale;
	pBuyMenuButtonBuy->w = 80 * scale;
	pBuyMenuButtonBuy->h = 19 * scale;

	pBuyMenuButtonClose->x = 504 * scale;
	pBuyMenuButtonClose->y = 385 * scale;
	pBuyMenuButtonClose->w = 60 * scale;
	pBuyMenuButtonClose->h = 19 * scale;


	pBuyMenuLabelSlot->x = 234 * scale;
	pBuyMenuLabelSlot->y = 298 * scale;
	pBuyMenuLabelSlot->w = 140 * scale;
	pBuyMenuLabelSlot->h = 22 * scale;
	
	pBuyMenuImageSlot->x = 234 * scale;
	pBuyMenuImageSlot->y = 298 * scale;
	pBuyMenuImageSlot->w = 140 * scale;
	pBuyMenuImageSlot->h = 22 * scale;

	pBuyMenuButtonSlot[0]->x = 237 * scale;
	pBuyMenuButtonSlot[0]->y = 299 * scale;
	pBuyMenuButtonSlot[0]->w = 21 * scale;
	pBuyMenuButtonSlot[0]->h = 21 * scale;

	pBuyMenuButtonSlot[1]->x = 350 * scale;
	pBuyMenuButtonSlot[1]->y = 299 * scale;
	pBuyMenuButtonSlot[1]->w = 21 * scale;
	pBuyMenuButtonSlot[1]->h = 21 * scale;


	// 检查模式
	if(g_iMod)
	{
		if(g_iMod == MOD_NONE || g_iMod == MOD_ZBS || g_iMod == MOD_FUNMODE)
		{
			for(int i=0;i<=1;i++)
			{
				for(int j=0;j<=4;j++)
				{
					pBuyMenuImageQuickBuy[i][j]->SetVisible(false);
				}
				pBuyMenuButtonFav[i]->m_bEnabled2 = false;
			}
	
			pBuyMenuPanelImageTimer[0]->SetVisible(true);
			pBuyMenuPanelLabelTimer[0]->SetVisible(true);
			pBuyMenuPanelLabelTimer2[0]->SetVisible(true);			
	
			pBuyMenuButtonBuy->SetVisible(false);
			pBuyMenuButtonClose->SetVisible(false);
	
		}
		else
		{
			for(int i=0;i<=1;i++)
			{
				for(int j=0;j<=4;j++)
				{
					pBuyMenuImageQuickBuy[i][j]->SetVisible(true);
				}
				pBuyMenuButtonFav[i]->m_bEnabled2 = true;
			}
	
			pBuyMenuPanelImageTimer[0]->SetVisible(false);
			pBuyMenuPanelLabelTimer[0]->SetVisible(false);
			pBuyMenuPanelLabelTimer2[0]->SetVisible(false);
	
			pBuyMenuButtonBuy->SetVisible(true);
			pBuyMenuButtonClose->SetVisible(true);		

		}
		if(g_iMod != MOD_TDM && g_iMod != MOD_DM && g_iMod != MOD_BC && g_iMod != MOD_HD && g_iMod != MOD_SD && g_iMod != MOD_ZBS && g_iMod != MOD_ZB4)
		{
			pBuyMenuPanelImageTimer[1]->SetVisible(true);
			pBuyMenuPanelLabelTimer[1]->SetVisible(true);
			pBuyMenuPanelLabelTimer2[1]->SetVisible(true);
			for(int i=0;i<=4;i++)
			{									
				pBuyMenuButtonFav[i]->SetVisible(true);
				pBuyMenuImageFavKey[i]->SetVisible(true);
				pBuyMenuLabelFavKey[i]->SetVisible(true);
				for(int j=0;j<=2;j++)
				{
					pBuyMenuImageFavWpn[i][j]->SetVisible(true);
				}
			}
			pBuyMenuButton2[0]->SetVisible(true);
			pBuyMenuButton2[1]->SetVisible(true);
		}
		else
		{
			pBuyMenuPanelImageTimer[1]->SetVisible(false);
			pBuyMenuPanelLabelTimer[1]->SetVisible(false);
			pBuyMenuPanelLabelTimer2[1]->SetVisible(false);

			for(int i=0;i<=4;i++)
			{									
				pBuyMenuButtonFav[i]->SetVisible(false);
				pBuyMenuImageFavKey[i]->SetVisible(false);
				pBuyMenuLabelFavKey[i]->SetVisible(false);
				for(int j=0;j<=2;j++)
				{
					pBuyMenuImageFavWpn[i][j]->SetVisible(false);
				}
			}
			pBuyMenuButton2[0]->SetVisible(false);
			pBuyMenuButton2[1]->SetVisible(false);
		}
		if(g_iMod != MOD_TDM && g_iMod != MOD_DM && g_iMod != MOD_BC && g_iMod != MOD_HD && g_iMod != MOD_SD && g_iMod != MOD_ZB4)
		{
			pBuyMenuImageSlot->SetVisible(false);
			pBuyMenuButtonSlot[0]->SetVisible(false);
			pBuyMenuButtonSlot[1]->SetVisible(false);
			pBuyMenuLabelSlot->SetVisible(false);
			pBuyMenuButtonBuy->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_BUY"));
		}
		else
		{
			pBuyMenuImageSlot->SetVisible(true);
			pBuyMenuButtonSlot[0]->SetVisible(true);
			pBuyMenuButtonSlot[1]->SetVisible(true);
			pBuyMenuLabelSlot->SetVisible(true);
			pBuyMenuButtonBuy->SetLabel(GetLangUni("CSBTE_BUYMENUPANEL_SAVESUIT"));
		}
	}
}

void BTEPanel_BuyMenu_SetTime(void)
{
	wchar_t sz[32];
	swprintf(sz,31,L"%d",g_iBuyTime - (int)g_flTime);
	if(g_iBuyTime - (int)g_flTime < 0)
		pBuyMenuPanelLabelTimer2[1]->SetLabel(L"0");
	else
		pBuyMenuPanelLabelTimer2[1]->SetLabel(sz);
}
void BTEPanel_BuyMenu_SetMoney(void)
{
	wchar_t sz[32];
	swprintf(sz,31,L"%d",g_iMoney);
	pBuyMenuPanelLabelTimer2[0]->SetLabel(sz);
}

void BTEPanel_BuyMenu_SetFav(int iSlot)
{
	pBuyMenuImageFavWpn[iSlot][0]->m_iTexture = pBuyMenuImageQuickBuy[1][0]->m_iTexture;
	pBuyMenuImageFavWpn[iSlot][1]->m_iTexture = pBuyMenuImageQuickBuy[1][1]->m_iTexture;
	pBuyMenuImageFavWpn[iSlot][2]->m_iTexture = pBuyMenuImageQuickBuy[1][4]->m_iTexture;
	pBuyMenuButtonFav[iSlot]->SetImage("gfx\\ui\\panel\\favoritebg","gfx\\ui\\panel\\select","gfx\\ui\\panel\\select");
	pBuyMenuButtonFav[iSlot]->SetEnabled(true);

	for(int i=0;i<=3;i++)
	{
		sprintf(szFavWpn[iSlot][i],"%s",szFavWpn[5][i]);
		char szText[16];
		sprintf(szText,"QuickBuy%d",iSlot+1);
		WritePrivateProfileString(szText,QUICKBUY_INI[i],szFavWpn[iSlot][i],configPathFavWpn);
	}

	char szCmd[256];
	sprintf(szCmd,"bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;secammo;primammo;vesthelm;defuser",szFavWpn[5][0],szFavWpn[5][1],szFavWpn[5][2],szFavWpn[5][3]);
	pBuyMenuButtonFav[iSlot]->SetCommand(szCmd);
}
int BTEPanel_BuyMenu_Read(int iSlot)
{
	int iCheck = 0;
	char name[16];
	sprintf(name,"QuickBuy%d",iSlot+1);
	for(int i=0;i<=3;i++)
	{
		GetPrivateProfileStringA(name,QUICKBUY_INI[i],"",szFavWpn[iSlot][i],sizeof(szFavWpn[iSlot][i]),configPathFavWpn);		
		if(strlen(szFavWpn[iSlot][i]))
		{
			char wpnname[64];
			sprintf(wpnname,"gfx\\vgui\\%s",szFavWpn[iSlot][i]);
			if(i<3)	pBuyMenuImageFavWpn[iSlot][i]->SetTexture(wpnname);			
			iCheck = 1;
		}
	}
	char szCmd[256];
	sprintf(szCmd,"bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;secammo;primammo;vesthelm;defuser",szFavWpn[iSlot][0],szFavWpn[iSlot][1],szFavWpn[iSlot][2],szFavWpn[iSlot][3]);
	pBuyMenuButtonFav[iSlot]->SetCommand(szCmd);
	return iCheck;
}

void BTEPanel_BuyMenu_SetQuickBuy(int iSlot, char *pItems)
{
	char name[32];
	int iSlot2 = iSlot;
	if(iSlot == 4) iSlot2 = 3;
	if(iSlot == 3) iSlot2 = 5;
	iSlot2 -= 1;
	sprintf(name,"gfx\\vgui\\%s",pItems);
	pBuyMenuImageQuickBuy[1][iSlot2]->SetTexture(name);
	sprintf(szFavWpn[5][iSlot-1],"%s",pItems);

	if(g_iMod != MOD_TDM && g_iMod != MOD_DM && g_iMod != MOD_BC && g_iMod != MOD_HD && g_iMod != MOD_SD && g_iMod != MOD_ZB4)
	{
		char szCmd[256];
		sprintf(szCmd,"bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;bte_buy_wpn %s;secammo;primammo;vesthelm;defuser",szFavWpn[5][0],szFavWpn[5][1],szFavWpn[5][2],szFavWpn[5][3]);
		pBuyMenuButtonBuy->SetCommand(szCmd);
		pBuyMenuButtonBuy->SetType(MGUI_BUTTON_TYPE_CLOSEALL);

		for(int i=0;i<=3;i++)
		{			
			char szText[16];
			sprintf(szText,"QuickBuy%d",0);
			WritePrivateProfileString(szText,QUICKBUY_INI[i],szFavWpn[5][i],configPathFavWpn);
		}
	}
	else
	{
		pBuyMenuButtonBuy->SetCommand("MGUI.SaveTeamSuit");
		pBuyMenuButtonBuy->SetType(MGUI_BUTTON_TYPE_COMMAND_CLOSEPANEL);
	}
}