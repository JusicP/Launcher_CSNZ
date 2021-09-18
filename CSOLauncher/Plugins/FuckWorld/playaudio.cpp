#include <winsani_in.h>
#include <windows.h>
#include <winsani_out.h>
#include <stdio.h>
#include <malloc.h>
#include <interface.h>
#include <metahook.h>
#include <process.h>
#include <VGUI\ISurface.h>
#include <const.h>
#include <cvardef.h>
#include <triangleapi.h>
//#include "exportfuncs.h"
#include "engfuncs.h"

#include "playaudio.h"
#include "fmod\fmod.h"
#include "BaseUI.h"

#define MUSIC_MAX		10
#define ME_LEFTCLICK	1
#define ME_RIGHTCLICK	2
#define ME_WHEELCLICK	4


struct PLAYPARAMS
{
	int type;
	char sound[64];
};

HMODULE g_hFMOD;
PLAYPARAMS g_sParams;

cvar_t *MP3Volume = NULL;
int g_iMenuActive = 0;
int g_iMouseEvent,g_iMouseOldEvent;
int g_iMusic_Length;
SCREENINFO g_sScreenInfo2;
int g_iPlayStatus = 0;
int g_iPausePosition = 0;
char g_szMusicName[64];
int g_iDrawList = 1;
char g_szMusicList[MUSIC_MAX+1][64];
int g_iMusicCount = 0;
int g_iMini = 0;
int g_iMusicIndex = 0;
int g_iMusicSingleLoop = 0;
int g_iReadyToPlayIndexMusic = 0;
typedef struct
{
	bool initialied;
	float curvolume;

	FMOD_SYSTEM *system;
	FMOD_SOUND *sound;
	FMOD_CHANNEL *channel;
}
fmod_t;

fmod_t fmod;

FMOD_RESULT (F_API *g_pfnFMOD_System_Create)(FMOD_SYSTEM **system);
FMOD_RESULT (F_API *g_pfnFMOD_System_Release)(FMOD_SYSTEM *system);
FMOD_RESULT (F_API *g_pfnFMOD_System_PlaySound)(FMOD_SYSTEM *system, FMOD_CHANNELINDEX channelid, FMOD_SOUND *sound, FMOD_BOOL paused, FMOD_CHANNEL **channel);
FMOD_RESULT (F_API *g_pfnFMOD_Sound_SetMode)(FMOD_SOUND *sound, FMOD_MODE mode);
FMOD_RESULT (F_API *g_pfnFMOD_System_CreateSound)(FMOD_SYSTEM *system, const char *name_or_data, FMOD_MODE mode, FMOD_CREATESOUNDEXINFO *exinfo, FMOD_SOUND **sound);
FMOD_RESULT (F_API *g_pfnFMOD_Sound_Release)(FMOD_SOUND *sound);
FMOD_RESULT (F_API *g_pfnFMOD_System_GetChannelsPlaying)(FMOD_SYSTEM *system, int *channels);
FMOD_RESULT (F_API *g_pfnFMOD_System_Init)(FMOD_SYSTEM *system, int maxchannels, FMOD_INITFLAGS flags, void *extradriverdata);
FMOD_RESULT (F_API *g_pfnFMOD_System_Close)(FMOD_SYSTEM *system);
FMOD_RESULT (F_API *g_pfnFMOD_System_Update)(FMOD_SYSTEM *system);
FMOD_RESULT (F_API *g_pfnFMOD_Channel_GetVolume)(FMOD_CHANNEL *channel, float *volume);
FMOD_RESULT (F_API *g_pfnFMOD_Channel_SetVolume)(FMOD_CHANNEL *channel, float volume);
FMOD_RESULT (F_API *g_pfnFMOD_Sound_GetLength)  (FMOD_SOUND *sound, unsigned int *length, FMOD_TIMEUNIT lengthtype);
FMOD_RESULT (F_API *g_pfnFMOD_Channel_GetPosition)   (FMOD_CHANNEL *channel, unsigned int *position, FMOD_TIMEUNIT postype);
FMOD_RESULT (F_API *g_pfnFMOD_Channel_SetPaused)  (FMOD_CHANNEL *channel, FMOD_BOOL paused);
FMOD_RESULT (F_API *g_pfnFMOD_Channel_SetCallback)  (FMOD_CHANNEL *channel, FMOD_CHANNEL_CALLBACK callback);


FMOD_RESULT F_API FMOD_Channel_SetCallback  (FMOD_CHANNEL *channel, FMOD_CHANNEL_CALLBACK callback)
{
	return g_pfnFMOD_Channel_SetCallback(channel,callback);
}
FMOD_RESULT F_API FMOD_Channel_SetPaused ( FMOD_CHANNEL *channel, FMOD_BOOL paused)
{
	return g_pfnFMOD_Channel_SetPaused(channel,paused);
}
FMOD_RESULT F_API FMOD_Channel_GetPosition (FMOD_CHANNEL *channel, unsigned int *position, FMOD_TIMEUNIT postype)
{
	return g_pfnFMOD_Channel_GetPosition(channel,position,postype);
}
FMOD_RESULT F_API FMOD_Sound_GetLength(FMOD_SOUND *sound, unsigned int *length, FMOD_TIMEUNIT lengthtype)
{
	return g_pfnFMOD_Sound_GetLength(sound,length,lengthtype);
}
FMOD_RESULT F_API FMOD_System_Create(FMOD_SYSTEM **system)
{
	return g_pfnFMOD_System_Create(system);
}

FMOD_RESULT F_API FMOD_System_Release(FMOD_SYSTEM *system)
{
	return g_pfnFMOD_System_Release(system);
}

FMOD_RESULT F_API FMOD_System_PlaySound(FMOD_SYSTEM *system, FMOD_CHANNELINDEX channelid, FMOD_SOUND *sound, FMOD_BOOL paused, FMOD_CHANNEL **channel)
{
	return g_pfnFMOD_System_PlaySound(system, channelid, sound, paused, channel);
}

FMOD_RESULT F_API FMOD_Sound_SetMode(FMOD_SOUND *sound, FMOD_MODE mode)
{
	return g_pfnFMOD_Sound_SetMode(sound, mode);
}

FMOD_RESULT F_API FMOD_System_CreateSound(FMOD_SYSTEM *system, const char *name_or_data, FMOD_MODE mode, FMOD_CREATESOUNDEXINFO *exinfo, FMOD_SOUND **sound)
{
	return g_pfnFMOD_System_CreateSound(system, name_or_data, mode, exinfo, sound);
}

FMOD_RESULT F_API FMOD_Sound_Release(FMOD_SOUND *sound)
{
	return g_pfnFMOD_Sound_Release(sound);
}

FMOD_RESULT F_API FMOD_System_GetChannelsPlaying(FMOD_SYSTEM *system, int *channels)
{
	return g_pfnFMOD_System_GetChannelsPlaying(system, channels);
}

FMOD_RESULT F_API FMOD_System_Init(FMOD_SYSTEM *system, int maxchannels, FMOD_INITFLAGS flags, void *extradriverdata)
{
	return g_pfnFMOD_System_Init(system, maxchannels, flags, extradriverdata);
}

FMOD_RESULT F_API FMOD_System_Close(FMOD_SYSTEM *system)
{
	return g_pfnFMOD_System_Close(system);
}

FMOD_RESULT F_API FMOD_System_Update(FMOD_SYSTEM *system)
{
	return g_pfnFMOD_System_Update(system);
}

FMOD_RESULT F_API FMOD_Channel_GetVolume(FMOD_CHANNEL *channel, float *volume)
{
	return g_pfnFMOD_Channel_GetVolume(channel, volume);
}

FMOD_RESULT F_API FMOD_Channel_SetVolume(FMOD_CHANNEL *channel, float volume)
{
	return g_pfnFMOD_Channel_SetVolume(channel, volume);
}
int g_iUI_Mouse;
int g_iUI_Play,g_iUI_Stop,g_iUI_Pause,g_iUI_Next,g_iUI_Prev;

const char *FileExtension2( const char *in )
{
	const char *separator, *backslash, *colon, *dot;

	separator = strrchr( in, '/' );
	backslash = strrchr( in, '\\' );
	if( !separator || separator < backslash ) separator = backslash;
	colon = strrchr( in, ':' );
	if( !separator || separator < colon ) separator = colon;

	dot = strrchr( in, '.' );
	if( dot == NULL || ( separator && ( dot < separator )))
		return "";
	return dot + 1;
}
const char *p[11]={"mp3","ogg","dls","flac","mp2","raw","s3m","wav","wma","xm","fsb"};
bool PlayAudio_CheckIsMusic(const char *pName)
{
	for(int i=0;i<11;i++)
	{
		char *pExt = (char *)FileExtension2(pName);
		if(strstr(pExt,p[i])) return 1;
	}
	return 0;
}
wchar_t *ANSIToUnicode2( const char* str )
{
   int textlen ;
   static wchar_t result[1024];
   textlen = MultiByteToWideChar( CP_ACP, 0, str,-1, NULL,0 ); 
   memset(result, 0, sizeof(char) * ( textlen + 1 ) );
   MultiByteToWideChar(CP_ACP, 0,str,-1,(LPWSTR)result,textlen ); 
   return result; 
}
char *UnicodeToANSI2( const wchar_t* str )
{
     static char result[1024];
     int textlen;
     textlen = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL );
     memset(result, 0, sizeof(char) * ( textlen + 1 ) );
     WideCharToMultiByte( CP_ACP, 0, str, -1, result, textlen, NULL, NULL );
     return result;
}
wchar_t *UTF8ToUnicode2( const char* str )
{
     int textlen ;
     static wchar_t result[1024];
     textlen = MultiByteToWideChar( CP_UTF8, 0, str,-1, NULL,0 ); 
     memset(result, 0, sizeof(char) * ( textlen + 1 ) );
     MultiByteToWideChar(CP_UTF8, 0,str,-1,(LPWSTR)result,textlen ); 
     return result; 
}
char *UnicodeToUTF82( const wchar_t* str )
{
	static char result[1024];
	int textlen;
	textlen = WideCharToMultiByte( CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL );
	memset(result, 0, sizeof(char) * ( textlen + 1 ) );
	WideCharToMultiByte( CP_UTF8, 0, str, -1, result, textlen, NULL, NULL );
	return result;
}
int PlayAudio_SearchFile(void)
{
	g_iMusicCount = 0;
	FileFindHandle_t findHandle;
	const char *result = g_pFileSystem->FindFirst("music/*.*", &findHandle, "GAME");
	while (result)
	{
		if(!PlayAudio_CheckIsMusic(result)) 
		{
			result = g_pFileSystem->FindNext(findHandle);
			continue;
		}
		g_iMusicCount ++;
		if(g_iMusicCount>MUSIC_MAX) return 10;

		sprintf(g_szMusicList[g_iMusicCount],"music/%s",UnicodeToUTF82(ANSIToUnicode2(result)));
		result = g_pFileSystem->FindNext(findHandle);
	}
	g_pFileSystem->FindClose(findHandle);
	return g_iMusicCount;
}
FMOD_RESULT F_CALLBACK Audio_Channel_CallBack(FMOD_CHANNEL *channel, FMOD_CHANNEL_CALLBACKTYPE type, void *commanddata1, void *commanddata2)
{
	if(type == FMOD_CHANNEL_CALLBACKTYPE_END)
	{
		char cmd[128];
		if(g_iMusicSingleLoop)
		{					
			sprintf(cmd,"fmod %s",g_szMusicList[g_iMusicIndex]);
			gEngfuncs.pfnClientCmd(cmd);
			return FMOD_OK;
		}
		g_iMusicIndex ++;
		if(g_iMusicIndex > g_iMusicCount)
		{
			g_iMusicIndex = 1;
		}
		g_iReadyToPlayIndexMusic = g_iMusicIndex;
		sprintf(cmd,"fmod play %s",g_szMusicList[g_iMusicIndex]);
		gEngfuncs.pfnClientCmd(cmd);
		return FMOD_OK;
	}
}
void UI_Init(void)
{
	g_iUI_Mouse = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iUI_Mouse,"gfx\\ui\\mouse\\mouse",1,1);
	g_iUI_Play = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iUI_Play,"gfx\\ui\\music_player\\play",1,1);
	g_iUI_Stop = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iUI_Stop,"gfx\\ui\\music_player\\stop",1,1);
	g_iUI_Pause = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iUI_Pause,"gfx\\ui\\music_player\\pause",1,1);
	g_iUI_Next = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iUI_Next,"gfx\\ui\\music_player\\next",1,1);
	g_iUI_Prev = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iUI_Prev,"gfx\\ui\\music_player\\prev",1,1);
	g_sScreenInfo2.iSize = sizeof(g_sScreenInfo2);
	gEngfuncs.pfnGetScreenInfo(&g_sScreenInfo2);

	PlayAudio_SearchFile();
}
bool IsClick(void)
{
	bool b =  (!(g_iMouseEvent & ME_LEFTCLICK) && (g_iMouseOldEvent & ME_LEFTCLICK));
	if(b)
	{
		g_iMouseEvent = 0;
		g_iMouseOldEvent = 0;
	}
	return b;
}
void UI_Draw(void)
{
	static int iMouseX,iMouseY;
	static float fPercent;
	static unsigned int iPos;
	PlayAudio_Frame();
	gEngfuncs.GetMousePosition(&iMouseX,&iMouseY);
	FMOD_Channel_GetPosition(fmod.channel,&iPos,FMOD_TIMEUNIT_MS);
	if(g_iMusic_Length == 0 || iPos<0) 
	{
		iPos = 0;
		g_iMusic_Length = 1;
	}
	fPercent = float(iPos) / float(g_iMusic_Length) * 320;
	// UI
	if(g_iMini)	
	{
		gEngfuncs.pfnFillRGBA(20,20,320,10,100,100,100,100);
		gEngfuncs.pfnFillRGBA(20,20,fPercent,10,255,255,0,255);
		if(g_iMenuActive)
		{
			if(iMouseX >20 && iMouseX<20+320 && iMouseY>20 && iMouseY<20 +10)
			{
				if(IsClick()) g_iMini = 1-g_iMini;
			}
			gEngfuncs.pTriAPI->RenderMode( kRenderTransTexture );
			g_pSurface->DrawSetColor(255,255,255,255);
			g_pSurface->DrawSetTexture(g_iUI_Mouse);
			g_pSurface->DrawTexturedRect(iMouseX,iMouseY,iMouseX+32,iMouseY+32);
		}
		return;
	}
	if(!g_iMenuActive) return;
	int StartX,StartY;
	StartX = StartY = 100;

	if(!g_iMini)
	{
		if(iMouseX >100 && iMouseX<100+320 && iMouseY>100 && iMouseY<StartY +10)
		{
			if(IsClick())
			{
				g_iMini = 1-g_iMini;
				g_iMenuActive = 0;
			}
		}
		gEngfuncs.pfnFillRGBA(100,100,320,10,100,100,100,100);
		gEngfuncs.pfnFillRGBA(100,100,fPercent,10,255,255,0,255);
	}

	// Status
	// LOOP
	if(iMouseX >100 && iMouseX<100+20 && iMouseY>75 && iMouseY<75 +20)
	{
		if(IsClick()) g_iMusicSingleLoop = 1-g_iMusicSingleLoop;
	}
	if(!g_iMusicSingleLoop) gEngfuncs.pfnFillRGBA(100,75,20,20,100,100,100,100);
	else gEngfuncs.pfnFillRGBA(100,75,20,20,255,255,100,100);

	char szPrint[256];
	
	if(g_iPlayStatus == 1 || g_iPlayStatus == 2)
	{
		// millsec -> sec
		iPos /= 1000;
		int iTime[4];
		iTime[0] = iPos / 60;
		iTime[1] = iPos % 60;
		iTime[2] = (g_iMusic_Length/1000) / 60;
		iTime[3] = (g_iMusic_Length/1000) % 60;
		sprintf(szPrint,"%s [%02d:%02d / %02d:%02d] %s",g_iPlayStatus == 1?"Playing.":"Looping.",iTime[0],iTime[1],iTime[2],iTime[3],&g_szMusicName[1]);
	}
	else if(g_iPlayStatus == 3)
	{
		sprintf(szPrint,"Paused. :%s",&g_szMusicName[1]);
	}
	else sprintf(szPrint,"Idle.");
	gEngfuncs.pfnDrawSetTextColor(1,1,0);
	gEngfuncs.pfnDrawConsoleString(StartX+30,StartY-g_sScreenInfo2.iCharHeight - 3,szPrint);

	// Draw Btn
	StartY += 20;
	gEngfuncs.pTriAPI->RenderMode( kRenderTransTexture );
	g_pSurface->DrawSetColor(255,255,255,255);

	if(iMouseX >StartX && iMouseX<StartX+32 && iMouseY>StartY && iMouseY<StartY +32)
	{
		if(g_iMouseEvent & ME_LEFTCLICK) g_pSurface->DrawSetColor(150,150,150,255);
		else g_pSurface->DrawSetColor(255,255,255,255);
		if(IsClick())
		{
			char cmd[64];
			g_iMusicIndex --;
			if(g_iMusicIndex == 0) g_iMusicIndex = g_iMusicCount;
			g_iReadyToPlayIndexMusic = g_iMusicIndex;
			sprintf(cmd,"fmod %s",g_szMusicList[g_iMusicIndex]);
			gEngfuncs.pfnClientCmd(cmd);
		}
	}
	else g_pSurface->DrawSetColor(255,255,255,80);
	g_pSurface->DrawSetTexture(g_iUI_Prev);
	g_pSurface->DrawTexturedRect(StartX,StartY,StartX+32,StartY+32);


	StartX += 40;
	if(iMouseX >StartX && iMouseX<StartX+32 && iMouseY>StartY && iMouseY<StartY +32)
	{
		if(g_iMouseEvent & ME_LEFTCLICK) g_pSurface->DrawSetColor(255,255,255,200);
		else g_pSurface->DrawSetColor(255,255,255,255);

		if(IsClick())
		{
			if(g_iPlayStatus == 3) gEngfuncs.pfnClientCmd("fmod continue");
			else  gEngfuncs.pfnClientCmd("fmod pause");
		}

	}
	else g_pSurface->DrawSetColor(255,255,255,80);
	g_pSurface->DrawSetTexture(g_iPlayStatus==3?g_iUI_Play:g_iUI_Pause);
	g_pSurface->DrawTexturedRect(StartX,StartY,StartX+32,StartY+32);

	StartX += 40;
	if(iMouseX >StartX && iMouseX<StartX+32 && iMouseY>StartY && iMouseY<StartY +32)
	{
		if(g_iMouseEvent & ME_LEFTCLICK) g_pSurface->DrawSetColor(255,255,255,200);
		else g_pSurface->DrawSetColor(255,255,255,255);
		if(IsClick()) gEngfuncs.pfnClientCmd("fmod stop");
	}
	else g_pSurface->DrawSetColor(255,255,255,80);
	g_pSurface->DrawSetTexture(g_iUI_Stop);
	g_pSurface->DrawTexturedRect(StartX,StartY,StartX+32,StartY+32);

	StartX += 40;
	if(iMouseX >StartX && iMouseX<StartX+32 && iMouseY>StartY && iMouseY<StartY +32)
	{
		if(g_iMouseEvent & ME_LEFTCLICK) g_pSurface->DrawSetColor(255,255,255,200);
		else g_pSurface->DrawSetColor(255,255,255,255);
		if(IsClick())
		{
			char cmd[64];
			g_iMusicIndex ++;
			if(g_iMusicIndex > g_iMusicCount) g_iMusicIndex = 1;
			g_iReadyToPlayIndexMusic = g_iMusicIndex;
			sprintf(cmd,"fmod %s",g_szMusicList[g_iMusicIndex]);
			gEngfuncs.pfnClientCmd(cmd);
		}
	}
	else g_pSurface->DrawSetColor(255,255,255,80);
	g_pSurface->DrawSetTexture(g_iUI_Next);
	g_pSurface->DrawTexturedRect(StartX,StartY,StartX+32,StartY+32);

	StartX += 50;

	if(iMouseX >StartX && iMouseX<StartX+150 && iMouseY>StartY-4 && iMouseY<StartY-4+32)
	{
		if(IsClick()) g_iMenuActive = 0;//g_iDrawList = 1-g_iDrawList;
		gEngfuncs.pfnFillRGBA(StartX,StartY-2,150,32,255,255,100,100);
	}
	else
	{
		if(g_iDrawList) gEngfuncs.pfnFillRGBA(StartX,StartY-2,150,32,255,255,100,100);
		else gEngfuncs.pfnFillRGBA(StartX,StartY-2,150,32,100,100,100,100);	
	}
	gEngfuncs.pfnDrawSetTextColor(1,1,1);
	gEngfuncs.pfnDrawConsoleString(StartX+55,StartY+5,g_iDrawList?"Close":" Open");
	if(!g_iDrawList)
	{
		gEngfuncs.pTriAPI->RenderMode( kRenderTransTexture );
		g_pSurface->DrawSetColor(255,255,255,255);
		g_pSurface->DrawSetTexture(g_iUI_Mouse);
		g_pSurface->DrawTexturedRect(iMouseX,iMouseY,iMouseX+32,iMouseY+32);
		return;
	}
	// Draw Files List
	StartX = 100;
	StartY = 100;

	StartY += 60;
	if(g_iMusicCount)
	{
		for(int i=1;i<=g_iMusicCount;i++)
		{
			// Draw BG
			if(iMouseX >StartX && iMouseX<StartX+300 && iMouseY>StartY+(i-1)*(g_sScreenInfo2.iCharHeight+5)-2 && iMouseY<StartY+(i-1)*(g_sScreenInfo2.iCharHeight+5)-2 +g_sScreenInfo2.iCharHeight)
			{
				if(g_iMouseEvent & ME_LEFTCLICK) gEngfuncs.pfnFillRGBA(StartX,StartY+(i-1)*(g_sScreenInfo2.iCharHeight+5)-2, 320,g_sScreenInfo2.iCharHeight,100,100,100,100);
				else gEngfuncs.pfnFillRGBA(StartX,StartY+(i-1)*(g_sScreenInfo2.iCharHeight+5)-2, 320,g_sScreenInfo2.iCharHeight,255,255,100,100);
				sprintf(szPrint,"fmod %s",g_szMusicList[i]);
				if(IsClick()) 
				{
					g_iMusicIndex = i;
					g_iReadyToPlayIndexMusic = g_iMusicIndex;
					gEngfuncs.pfnClientCmd(szPrint);
				}
			}
			else gEngfuncs.pfnFillRGBA(StartX,StartY+(i-1)*(g_sScreenInfo2.iCharHeight+5)-2, 320,g_sScreenInfo2.iCharHeight,100,100,100,100);

			if(g_iMusicIndex == i && g_iPlayStatus && g_iPlayStatus<3)
			{
				static char playeffect[4];
				static int f,mod;
				f = (int)gEngfuncs.GetClientTime();
				mod = f % 3;
				for(int i=0;i<=mod;i++)
				{
					playeffect[i] = '>';
				}
				playeffect[mod+1] = '\0';
				gEngfuncs.pfnDrawSetTextColor(0,1,0);
				gEngfuncs.pfnDrawConsoleString(StartX+320 - 50,StartY+(i-1)*(g_sScreenInfo2.iCharHeight+5),playeffect);
			}

			sprintf(szPrint,"%02d.%s",i,g_szMusicList[i]);
			gEngfuncs.pfnDrawSetTextColor(1,1,1);
			gEngfuncs.pfnDrawConsoleString(StartX,StartY+(i-1)*(g_sScreenInfo2.iCharHeight+5),szPrint);
		}
	}
	// Draw Mouse
	gEngfuncs.pTriAPI->RenderMode( kRenderTransTexture );
	g_pSurface->DrawSetColor(255,255,255,255);
	g_pSurface->DrawSetTexture(g_iUI_Mouse);
	g_pSurface->DrawTexturedRect(iMouseX,iMouseY,iMouseX+32,iMouseY+32);
}

unsigned __stdcall PlayAudio_FMOD(void *p)
{
	PLAYPARAMS *params = (PLAYPARAMS *)p;
	int iPlayType = params->type;
	char sound[128];
	sprintf(sound,"%s",params->sound);
	bool loop = (iPlayType == 2);
	if(iPlayType == 0) // stop
	{
		g_iPlayStatus = 0;
		sprintf(g_szMusicName,"No music");
		int playing = 0;
		FMOD_System_GetChannelsPlaying(fmod.system, &playing);
		if (playing)
		{
			FMOD_Sound_Release(fmod.sound);
			fmod.sound = NULL;
		}
		return 0;
	}
	else if(iPlayType == 1 || iPlayType == 2) // play / loop
	{
		if(g_iReadyToPlayIndexMusic)
		{
			sprintf(sound,"%s",UnicodeToANSI2(UTF8ToUnicode2(g_szMusicList[g_iReadyToPlayIndexMusic])));
		}
		g_iPlayStatus = iPlayType;
		char name[128];
		sprintf(name,"%s",strrchr(sound,'\\'));
		if(!strcmp(name,"(null)")) sprintf(name,"%s",strrchr(sound,'/'));
		if(!strcmp(name,"(null)")) sprintf(name,"%s",sound);
		sprintf(g_szMusicName,"%s",UnicodeToUTF82(ANSIToUnicode2(name)));
		int playing = 0;
		FMOD_System_GetChannelsPlaying(fmod.system, &playing);

		if (playing)
			FMOD_Sound_Release(fmod.sound);

		char fullPath[MAX_PATH];
		g_pFileSystem->GetLocalPath(sound, fullPath, sizeof(fullPath));

		if (FMOD_System_CreateSound(fmod.system, fullPath, FMOD_SOFTWARE, 0, &fmod.sound) != FMOD_OK)
		{
			g_iPlayStatus = 0;
			g_iMusic_Length = 0;
			gEngfuncs.Con_Printf("[FMOD]: Could not load %s\n", sound);
			return 0;
		}

		FMOD_Sound_SetMode(fmod.sound, loop ? FMOD_LOOP_NORMAL : FMOD_LOOP_OFF);
		if (FMOD_System_PlaySound(fmod.system, FMOD_CHANNEL_FREE, fmod.sound, 0, &fmod.channel) != FMOD_OK)
		{
			

			g_iPlayStatus = 0;
			g_iMusic_Length = 0;
			gEngfuncs.Con_Printf("[FMOD]: Could not play %s\n", sound);
			return 0;
		}
		if (FMOD_Channel_SetCallback(fmod.channel,Audio_Channel_CallBack) == FMOD_OK) 
		{
			FMOD_System_Update(fmod.system);
		}
		unsigned int i;
		FMOD_Sound_GetLength(fmod.sound,&i,FMOD_TIMEUNIT_MS);
		g_iMusic_Length = i;
		if(g_iReadyToPlayIndexMusic) g_iReadyToPlayIndexMusic = 0;
	}
	else if(iPlayType == 3) // pause
	{
		g_iPlayStatus = 3;
		int playing = 0;
		FMOD_System_GetChannelsPlaying(fmod.system, &playing);
		if (playing)
		{
			if (FMOD_Channel_SetPaused(fmod.channel,true) != FMOD_OK)
			{
				gEngfuncs.Con_Printf("[FMOD]: Could not pause \n");
				return 0;
			}
		}
	}
	else if(iPlayType == 4) // continue
	{
		if (FMOD_Channel_SetPaused(fmod.channel,false) != FMOD_OK)
		{
			gEngfuncs.Con_Printf("[FMOD]: Could not continue \n");
			return 0;
		}
		else g_iPlayStatus = 1;
	}
}


void FMOD_f(void)
{
	PlayAudio_Frame();
	if (!fmod.initialied)
	{
		return;
	}
	bool loop = false;
	HANDLE   hThread;
	unsigned  iThreadID;
	if(g_iReadyToPlayIndexMusic)
	{
		g_sParams.type = 1;
		sprintf(g_sParams.sound,"%s",g_szMusicList[g_iReadyToPlayIndexMusic]);
		hThread = (HANDLE)_beginthreadex( NULL,         // security  
                                   0,            // stack size  
                                   &PlayAudio_FMOD,  
                                   (void *)&g_sParams,           // arg list  
                                   0,  // so we can later call ResumeThread()  
                                   &iThreadID ); 
		return;
	}
	for (int i = 1; i < gEngfuncs.Cmd_Argc(); i++)
	{
		char *params = gEngfuncs.Cmd_Argv(i);

		if (!stricmp(params, "loop"))
		{
			loop = true;
		}
		else if (!stricmp(params, "stop"))
		{
			g_sParams.type = 0;
  
			hThread = (HANDLE)_beginthreadex( NULL,         // security  
                                   0,            // stack size  
                                   &PlayAudio_FMOD,  
                                   (void *)&g_sParams,           // arg list  
                                   0,  // so we can later call ResumeThread()  
                                   &iThreadID ); 
			//PlayAudio_FMOD(0,"");
			return;
		}
		else if (!stricmp(params, "pause"))
		{
			g_sParams.type = 3;
			hThread = (HANDLE)_beginthreadex( NULL,         // security  
                                   0,            // stack size  
                                   &PlayAudio_FMOD,  
                                   (void *)&g_sParams,           // arg list  
                                   0,  // so we can later call ResumeThread()  
                                   &iThreadID ); 
			//PlayAudio_FMOD(3,"");
			return;
		}
		else if (!stricmp(params, "continue"))
		{
			g_sParams.type = 4;
			hThread = (HANDLE)_beginthreadex( NULL,         // security  
                                   0,            // stack size  
                                   &PlayAudio_FMOD,  
                                   (void *)&g_sParams,           // arg list  
                                   0,  // so we can later call ResumeThread()  
                                   &iThreadID ); 
			//PlayAudio_FMOD(4,"");
			return;
		}
		else
		{
			if (strlen(params) > 0)
			{
				g_sParams.type = loop?2:1;
				sprintf(g_sParams.sound,"%s",params);
				hThread = (HANDLE)_beginthreadex( NULL,         // security  
                                   0,            // stack size  
                                   &PlayAudio_FMOD,  
                                   (void *)&g_sParams,           // arg list  
                                   0,  // so we can later call ResumeThread()  
                                   &iThreadID ); 
				//PlayAudio_FMOD(loop?1:2,params);
			}
		}
	}
}
/*
void FMOD_f(void)
{
	PlayAudio_Frame();
	if (!fmod.initialied)
	{
		if (!cmd_fmod)
			cmd_fmod = Cmd_FindCmd("mp3");

		cmd_fmod->function();
		return;
	}

	bool loop = false;

	for (int i = 1; i < gEngfuncs.Cmd_Argc(); i++)
	{
		char *params = gEngfuncs.Cmd_Argv(i);

		if (!stricmp(params, "loop"))
		{
			loop = true;
			g_iPlayStatus = 2;
		}
		else if (!stricmp(params, "stop"))
		{
			sprintf(g_szMusicName,"No music");
			int playing = 0;
			FMOD_System_GetChannelsPlaying(fmod.system, &playing);
			if (playing)
			{
				FMOD_Sound_Release(fmod.sound);
				fmod.sound = NULL;
			}
		}
		else if (!stricmp(params, "pause"))
		{
			g_iPlayStatus = 3;
			int playing = 0;
			FMOD_System_GetChannelsPlaying(fmod.system, &playing);

			if (playing)
			{
				
				if (FMOD_Channel_SetPaused(fmod.channel,true) != FMOD_OK)
				{
					gEngfuncs.Con_Printf("[FMOD]: Could not pause \n");
					return;
				}
			}
		}
		else if (!stricmp(params, "continue"))
		{
			g_iPlayStatus = 1;
				
			if (FMOD_Channel_SetPaused(fmod.channel,false) != FMOD_OK)
			{
				gEngfuncs.Con_Printf("[FMOD]: Could not continue \n");
				return;
			}
		}
		else
		{
			if (strlen(params) > 0)
			{
				sprintf(g_szMusicName,"%s",strrchr(params,'\\'));
				if(!strcmp(g_szMusicName,"(null)")) sprintf(g_szMusicName,"%s",strrchr(params,'/'));
				if(!strcmp(g_szMusicName,"(null)")) sprintf(g_szMusicName,"%s",params);
				int playing = 0;
				FMOD_System_GetChannelsPlaying(fmod.system, &playing);

				if (playing)
					FMOD_Sound_Release(fmod.sound);

				char fullPath[MAX_PATH];
				char *sound = params;
				g_pFileSystem->GetLocalPath(sound, fullPath, sizeof(fullPath));

				if (FMOD_System_CreateSound(fmod.system, fullPath, FMOD_SOFTWARE, 0, &fmod.sound) != FMOD_OK)
				{
					g_iPlayStatus = 0;
					g_iMusic_Length = 0;
					gEngfuncs.Con_Printf("[FMOD]: Could not load %s\n", sound);
					return;
				}

				FMOD_Sound_SetMode(fmod.sound, loop ? FMOD_LOOP_NORMAL : FMOD_LOOP_OFF);

				if (FMOD_System_PlaySound(fmod.system, FMOD_CHANNEL_FREE, fmod.sound, 0, &fmod.channel) != FMOD_OK)
				{
					g_iPlayStatus = 0;
					g_iMusic_Length = 0;
					gEngfuncs.Con_Printf("[FMOD]: Could not play %s\n", sound);
					return;
				}
				g_iPlayStatus = loop?2:1;
				unsigned int i;
				FMOD_Sound_GetLength(fmod.sound,&i,FMOD_TIMEUNIT_MS);
				g_iMusic_Length = i;

			}
		}
	}
}*/
void ShowMenu(void)
{
	g_iMenuActive = 1 - g_iMenuActive;
	gEngfuncs.pfnSetMouseEnable(g_iMenuActive);
}

void PlayAudio_Init(void)
{
	memset(&fmod, 0, sizeof(fmod));


	gEngfuncs.pfnAddCommand("fmod", FMOD_f);
	gEngfuncs.pfnAddCommand("musicmenu", ShowMenu);

	char fullPath[MAX_PATH];
	g_pFileSystem->GetLocalPath("fmodex.dll", fullPath, sizeof(fullPath));
	g_hFMOD = LoadLibrary(fullPath);

	if (!g_hFMOD)
		return;

	g_pfnFMOD_System_Create = (FMOD_RESULT (F_API *)(FMOD_SYSTEM **))GetProcAddress(g_hFMOD, "FMOD_System_Create");
	g_pfnFMOD_System_Release = (FMOD_RESULT (F_API *)(FMOD_SYSTEM *))GetProcAddress(g_hFMOD, "FMOD_System_Release");
	g_pfnFMOD_System_PlaySound = (FMOD_RESULT (F_API *)(FMOD_SYSTEM *, FMOD_CHANNELINDEX, FMOD_SOUND *, FMOD_BOOL, FMOD_CHANNEL **))GetProcAddress(g_hFMOD, "FMOD_System_PlaySound");
	g_pfnFMOD_Sound_SetMode = (FMOD_RESULT (F_API *)(FMOD_SOUND *, FMOD_MODE))GetProcAddress(g_hFMOD, "FMOD_Sound_SetMode");
	g_pfnFMOD_System_CreateSound = (FMOD_RESULT (F_API *)(FMOD_SYSTEM *, const char *, FMOD_MODE, FMOD_CREATESOUNDEXINFO *, FMOD_SOUND **))GetProcAddress(g_hFMOD, "FMOD_System_CreateSound");
	g_pfnFMOD_Sound_Release = (FMOD_RESULT (F_API *)(FMOD_SOUND *))GetProcAddress(g_hFMOD, "FMOD_Sound_Release");
	g_pfnFMOD_System_GetChannelsPlaying = (FMOD_RESULT (F_API *)(FMOD_SYSTEM *, int *))GetProcAddress(g_hFMOD, "FMOD_System_GetChannelsPlaying");
	g_pfnFMOD_System_Init = (FMOD_RESULT (F_API *)(FMOD_SYSTEM *, int, FMOD_INITFLAGS, void *))GetProcAddress(g_hFMOD, "FMOD_System_Init");
	g_pfnFMOD_System_Close = (FMOD_RESULT (F_API *)(FMOD_SYSTEM *))GetProcAddress(g_hFMOD, "FMOD_System_Close");
	g_pfnFMOD_System_Update = (FMOD_RESULT (F_API *)(FMOD_SYSTEM *))GetProcAddress(g_hFMOD, "FMOD_System_Update");
	g_pfnFMOD_Channel_SetVolume = (FMOD_RESULT (F_API *)(FMOD_CHANNEL *, float))GetProcAddress(g_hFMOD, "FMOD_Channel_SetVolume");
	g_pfnFMOD_Channel_GetVolume = (FMOD_RESULT (F_API *)(FMOD_CHANNEL *, float *))GetProcAddress(g_hFMOD, "FMOD_Channel_SetVolume");
	g_pfnFMOD_Sound_GetLength = (FMOD_RESULT (F_API *)(FMOD_SOUND *,unsigned int *,FMOD_TIMEUNIT))GetProcAddress(g_hFMOD, "FMOD_Sound_GetLength");
	g_pfnFMOD_Channel_GetPosition = (FMOD_RESULT (F_API *)(FMOD_CHANNEL *,unsigned int *,FMOD_TIMEUNIT))GetProcAddress(g_hFMOD, "FMOD_Channel_GetPosition");
	g_pfnFMOD_Channel_SetPaused = (FMOD_RESULT (F_API *)(FMOD_CHANNEL *,FMOD_BOOL paused))GetProcAddress(g_hFMOD, "FMOD_Channel_SetPaused");
	g_pfnFMOD_Channel_SetCallback = (FMOD_RESULT (F_API *)(FMOD_CHANNEL *,FMOD_CHANNEL_CALLBACK callback))GetProcAddress(g_hFMOD, "FMOD_Channel_SetCallback");

	if (FMOD_System_Create(&fmod.system) != FMOD_OK)
		return;

	if (FMOD_System_Init(fmod.system, 1, FMOD_INIT_NORMAL, NULL) != FMOD_OK)
		return;


	fmod.initialied = true;
}

void PlayAudio_Shutdown(void)
{
	if (fmod.initialied)
	{
		FMOD_System_Close(fmod.system);
		FMOD_System_Release(fmod.system);
	}

	if (g_hFMOD)
	{
		FreeLibrary(g_hFMOD);
	}
}

void PlayAudio_Frame(void)
{
	if (!fmod.initialied)
		return;

	if (!fmod.sound)
		return;

	if (!MP3Volume)
		MP3Volume = gEngfuncs.pfnGetCvarPointer("MP3Volume");

	float volume = 0.0;
	FMOD_Channel_GetVolume(fmod.channel, &volume);

	float cvar_volume = atof(MP3Volume->string) * 2;

	if (volume != cvar_volume)
		FMOD_Channel_SetVolume(fmod.channel, max(0, cvar_volume));

	FMOD_System_Update(fmod.system);
}