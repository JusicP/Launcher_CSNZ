
void BTEPanel_Init(void);
void BTEBuyMenu_Init(void);

void BTEPanel_TeamSuit_Reset(void);
void BTEPanel_TeamSuit_SetSlot(int iSlot);
void BTEPanel_TeamSuit_Save(void);
void BTEPanel_TeamSuit_Show(void);
void BTEPanel_TeamSuit_UpdateItems(int iSlot,char *pItems1,char *pItems2 ,char *pItems3, char *pIteam4);
void BTEPanel_BuyMenu_SetFav(int iSolt);
void BTEPanel_BuyMenu_SetQuickBuy(int iSlot, char *pItems);
void BTEPanel_BuyMenu_UpdateItems(int iSlot,char *pItems);
void BTEPanel_BuyMenu_SetHaveNextPage(int iHavePrevPage,int iHaveNextPage);
void BTEPanel_BuyMenu_SetPage(int page,int type);
void BTEPanel_BuyMenu_Close(void);
void BTEPanel_BuyMenu_Reset(void);

void BTEPanel_BuyMenu_SetMoney(void);
void BTEPanel_BuyMenu_SetTime(void);