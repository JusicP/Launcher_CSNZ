#include "base.h"

int EngFunc_ClCMD(char *p)
{	
	if((p[0] == 'm' &&p[1] == 'p' &&p[2] == '3' && p[3] == ' ') || (p[0] == 'c' && p[1] == 'd' && p[2] == ' '))
	{
#if _DEBUG
		gEngfuncs.Con_Printf("%s", p);
#endif
		
		char szPlayType[32],szMusic[64],szCmd[128];;
		int iPlay;

		char *pText = gEngfuncs.COM_ParseFile(p,szMusic);
		pText = gEngfuncs.COM_ParseFile(pText,szPlayType);
		if(!strcmp(szPlayType,"loop") || !strcmp(szPlayType,"loopfile"))
		{
			g_iPlayStatus = 2;
		}
		else if(!strcmp(szPlayType,"play"))
		{
			g_iPlayStatus = 1;
		}
		else if(!strcmp(szPlayType,"pause"))
		{
			g_iPlayStatus = 3;
		}
		else if(!strcmp(szPlayType,"stop"))
		{
			g_iPlayStatus = 0;
			gEngfuncs.pfnClientCmd(p);
			gEngfuncs.pfnClientCmd("fmod stop");
			return 0;
		}
		else
		{
			//gEngfuncs.Con_Printf("[FMOD]:Unknown play command:%s\n",szPlayType);
			return 0;
		}
		pText = gEngfuncs.COM_ParseFile(pText,szMusic);
		if(strlen(szMusic)==0)
		{
			//gEngfuncs.Con_Printf("[FMOD]:Bad music name");
			return 0;
		}
		else
		{
			//gEngfuncs.Con_Printf("[FMOD]:Try to play :%s\n",szMusic);
			sprintf(szCmd,"fmod %s %s",szPlayType,szMusic);
			gEngfuncs.pfnClientCmd(szCmd);
			return 0;
		}
		return 0;
	}
	return gEngfuncs.pfnClientCmd(p);
}