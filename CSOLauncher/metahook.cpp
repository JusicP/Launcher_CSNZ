#include <ws2tcpip.h>
#include <windows.h>
#include "metahook.h"
#include "Detours\detours.h"
#include "interface.h"
#include "interface\VGUI\IPanel.h"
#include "interface\IGameUI.h"
#include "interface\VGUI\IEngineVGui.h"
#include "interface\ICommandLine.h"
#include "ChattingManager.h"

#include <IPluginsV1.h>
#include <exception>

#include <fstream>
#include <iostream>
#include "XZip.h"
#include <dirent.h>
#include <filesystem>

namespace fs = std::filesystem;

using namespace std;

struct hook_s
{
	void *pOldFuncAddr;
	void *pNewFuncAddr;
	void *pClass;
	int iTableIndex;
	int iFuncIndex;
	HMODULE hModule;
	const char *pszModuleName;
	const char *pszFuncName;
	struct hook_s *pNext;
	void *pInfo;
};

cl_enginefunc_t *g_pEngine;
cl_enginefunc_t g_Engine;

void *g_pGameConsoleInput;
int(__thiscall*g_pfnGameConsoleInput)(char *a1, char *a2);
hook_t *g_phGameConsoleInput;

void *g_pSocketManagerConstructor;
void *(__thiscall*g_pfnSocketManagerConstructor)(void *_this);
hook_t *g_phSocketManagerConstructor;

void *g_pSocketManagerCSOTW2008;
int(__thiscall*g_pfnSocketManagerCSOTW2008)(void *_this, int a1, int a2);
hook_t *g_phSocketManagerCSOTW2008;

void *g_pSprintf;
int(*g_pfnSprintf)(char *a1, char *a2, ...);
hook_t *g_phSprintf;

void *g_pPacketRead;
int(__thiscall*g_pfnPacketRead)(void *__this, int a2, int a3, int a4);
hook_t *g_phPacketRead;

void *g_pPacket_Parse;
int(__thiscall*g_pfnPacket_Parse)(int _this, int Dst, int a3, int a4);
hook_t *g_phPacket_Parse;

void *g_pGameGuard_Init;
int(__thiscall*g_pfnGameGuard_Init)(void *__this);
hook_t *g_phGameGuard_Init;

void* g_pServerConnect;
int(__thiscall* g_pfnServerConnect)(void* __this, unsigned long a2, short a3, int a4);
hook_t* g_phServerConnect;

int(__thiscall* g_pfnGameUI_RunFrame)(void* _this);
typedef int(__thiscall* tShowLoginDlg)(void* mainPanelPtr);
tShowLoginDlg g_pfnShowLoginDlg;
void* g_pCSOMainPanel;

typedef void*(__thiscall* tPanel_FindChildByName)(void* _this, const char* name, bool recurseDown);
tPanel_FindChildByName g_pfnPanel_FindChildByName;

typedef int(__thiscall* tLoginDlg_OnCommand)(void* _this, const char* command);
tLoginDlg_OnCommand g_pfnLoginDlg_OnCommand;

void* g_pPacket_Metadata_Parse;
int(__thiscall* g_pfnPacket_Metadata_Parse)(void* _this, void* packetBuffer, int packetSize);
hook_t* g_phPacket_Metadata_Parse;

void* g_pPacket_Quest_Parse;
bool(__thiscall* g_pfnPacket_Quest_Parse)(void* _this, void* packetBuffer, int packetSize);
hook_t* g_phPacket_Quest_Parse;

void* g_pPacket_Host;
typedef int(__thiscall* tPacket_Host_Parse)(void* _this, void* packetBuffer, int packetSize);
tPacket_Host_Parse g_pfnPacket_Host_Parse;
hook_t* g_phPacket_Host_Parse;

typedef int (WINAPI* t_recvfrom) (SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen);
t_recvfrom g_pfnRecvfrom;

typedef int (WINAPI* t_sendto) (SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
t_sendto g_pfnSendto;

void* g_pEVP_DecryptUpdate;
int(*g_pfnEVP_DecryptUpdate)(void* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl);
hook_t* g_phEVP_DecryptUpdate;

/*
	CSOTW 2009
*/
void* g_pHackShield_UpdateInit;
int(__thiscall* g_pfnHackShield_UpdateInit)();
hook_t* g_phHackShield_UpdateInit;

void* g_pHackShield_DllInit;
int(__thiscall* g_pfnHackShield_DllInit)();
hook_t* g_phHackShield_DllInit;

void* g_pHackShield_Validate;
int(__thiscall* g_pfnHackShield_Validate)();
hook_t* g_phHackShield_Validate;

void* g_pUnkFunc;
void(*g_pfnUnkFunc)(int a1, int a2, char* a3);
hook_t* g_phUnkFunc;

void* g_pUnkFunc2;
void(*g_pfnUnkFunc2)(LPVOID lpMem);
hook_t* g_phUnkFunc2;


class CCSBotManager
{
public:
	virtual void Unknown() = NULL;
	virtual void Bot_Add(int side) = NULL;
};

CCSBotManager* g_pBotManager = NULL;

HMODULE g_hEngineModule;
DWORD g_dwEngineBase;
DWORD g_dwEngineSize;
DWORD g_dwGameUIBase;
DWORD g_dwGameUISize;
DWORD g_dwMpBase;
DWORD g_dwMpSize;

hook_t *g_pHookBase;

hook_t *FindInlineHooked(void *pOldFuncAddr);
hook_t *FindVFTHooked(void *pClass, int iTableIndex, int iFuncIndex);
hook_t *FindIATHooked(HMODULE hModule, const char *pszModuleName, const char *pszFuncName);
BOOL UnHook(hook_t *pHook);
hook_t *InlineHook(void *pOldFuncAddr, void *pNewFuncAddr, void *&pCallBackFuncAddr);
hook_t *VFTHook(void *pClass, int iTableIndex, int iFuncIndex, void *pNewFuncAddr, void *&pCallBackFuncAddr);
hook_t *IATHook(HMODULE hModule, const char *pszModuleName, const char *pszFuncName, void *pNewFuncAddr, void *&pCallBackFuncAddr);
void *GetClassFuncAddr(...);
DWORD GetModuleBase(HMODULE hModule);
DWORD GetModuleSize(HMODULE hModule);
void *SearchPattern(void *pStartSearch, DWORD dwSearchLen, char *pPattern, DWORD dwPatternLen);
void WriteDWORD(void *pAddress, DWORD dwValue);
DWORD ReadDWORD(void *pAddress);
DWORD WriteMemory(void *pAddress, BYTE *pData, DWORD dwDataSize);
DWORD ReadMemory(void *pAddress, BYTE *pData, DWORD dwDataSize);
DWORD GetVideoMode(int *wide, int *height, int *bpp, bool *windowed);
DWORD GetEngineVersion(void);
DWORD FindPattern(PCHAR pattern, PCHAR mask, DWORD start, DWORD end, DWORD offset);
DWORD FindPattern(PCHAR pattern, DWORD start, DWORD end, DWORD offset);
DWORD FindPush(DWORD start, DWORD end, PCHAR Message);

#define SOCKETMANAGER_SIG_CSOSGP "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x83\xEC\x0C\x89\x4D\xE8\x8B\x45\xE8\xC7\x40\x00\x00\x00\x00\x00"
#define SOCKETMANAGER_MASK_CSOSGP "xxxxxx????xx????xxxx????xxxxxxxxxxx?????"
#define NEXONMANAGER_SIG_CSOSGP "\x55\x8B\xEC\x83\xEC\x0C\x89\x4D\xF8\xE8\x00\x00\x00\x00\x8B\xC8"
#define NEXONMANAGER_MASK_CSOSGP "xxxxxxxxxxxxxxxx????"

#define SOCKETMANAGER_SIG_CSNZ19 "\x55\x8B\xEC\x51\x8A\x45\x08\x53"
#define SOCKETMANAGER_MASK_CSNZ19 "xxxxxxxx"

#define GAMECONSOLEINPUT_SIG_CSNZ19 "\x55\x8B\xEC\x83\xEC\x18\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\xFC\x53\x56"
#define GAMECONSOLEINPUT_MASK_CSNZ19 "xxxxxxx????xxxxxxx"

#define SOCKETMANAGER_SIG_CSNZ15 "\x55\x8B\xEC\x8A\x45\x08\x53" // also works in CSOIDN16
#define NEXONMANAGER_SIG_CSOIDN16 "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x51\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\x6A\x01"
#define NEXONMANAGER_MASK_CSOIDN16 "xxxxxx????xx????xxxxx????xxxxxxxx????xxxx"
#define PACKET_ROOMLIST_SIG_CSNZ15 "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\xF0\x56\x57\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF1\x8B\x45\x08"
#define PACKET_ROOMLIST_MASK_CSNZ15 "xxxxxx????xx????xxx????x????xxxxxxxxxxxxx????xxxxx"

#define PACKET_PARSE_SIG_CSNZ19 "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x34\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\xF0\x53\x56\x57\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\x45\x08"
#define PACKET_PARSE_MASK_CSNZ19 "xxxxxx????xx????xxxxx????xxxxxxxxxxxxxx????xxx"

#define GAMEGUARD_REPLY_SIG_CSOTW2008 "\x56\x8B\xF1\x80\x3E\x00\x75\x23"
#define GAMEGUARD_REPLY_MASK_CSOTW2008 "xxxxxxxx"

#define SOCKETMANAGER_SIG_CSOTW2008 "\x56\x57\x6A\x00\x6A\x00\x6A\x01\x8B\xF1\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x54\x24\x0C\x8D\x46\x2C"
#define SOCKETMANAGER_MASK_CSOTW2008 "xxxxxxxxxxx????x????xxxxxxx"
 
#define SPRINTF_SIG_CSNZ2019 "\x55\x8B\xEC\x8D\x45\x10\x50\x6A\x00\xFF\x75\x0C\x6A\xFF\xFF\x75\x08\xE8\x00\x00\x00\x00\x8B\x08\xFF\x70\x04\x83\xC9\x01\x51\xFF\x15\x00\x00\x00\x00\x83\xC9\xFF"
#define SPRINTF_MASK_CSNZ2019 "xxxxxxxxxxxxxxxxxx????xxxxxxxxxxx????xxx"

#define SERVERCONNECT_SIG_CSNZ2019 "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\xF0\x53\x56\x57\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF1\x8B\x4E\x04\x85\xC9\x74\x25\x8B\x01\x6A\x01\xFF\x10\x68\x00\x00\x00\x00"
#define SERVERCONNECT_MASK_CSNZ2019 "xxxxxx????xx????xxx????x????xxxxxxxxxxxxxx????xxxxxxxxxxxxxxxx????"

#define HACKSHIELD_UPDATEINIT_SIG_CSOTW2009 "\x6A\x01\xE8\x00\x00\x00\x00\x83\xC4\x04\x6A\x00"
#define HACKSHIELD_UPDATEINIT_MASK_CSOTW2009 "xxx????xxxxx"

#define HACKSHIELD_DLLINIT_SIG_CSOTW2009 "\x56\xFF\x15\x00\x00\x00\x00\x6A\x00\xA3\x00\x00\x00\x00"
#define HACKSHIELD_DLLINIT_MASK_CSOTW2009 "xxx????xxx????"

#define HACKSHIELD_VALIDATE_SIG_CSOTW2009 "\xE8\x00\x00\x00\x00\x85\xC0\xA3\x00\x00\x00\x00\xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\x74\x12"
#define HACKSHIELD_VALIDATE_MASK_CSOTW2009 "x????xxx????xx????????xx"

#define UNK_SIG_CSOTW2009 "x51\x8D\x54\x24\x20\x8B\xCC\x52\xE8\x00\x00\x00\x00\x8B\x74\x24\x1C\x56\xE8\x00\x00\x00\x00\x83\xC4\x18\x8B\xC6\x5E\xC3\x90"
#define UNK_MASK_CSOTW2009 "xxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxx????xxxxxx????xxxxxxxx"

#define UNK2_SIG_CSOTW2009 "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\x53\x56\x57\x83\x3D\x00\x00\x00\x00\x00"
#define UNK2_MASK_CSOTW2009 "xxxxx????xxxxx?????"

#define PARSE_W_UDP_SIG_CSNZ "\x55\x8B\xEC\x8B\x4D\x08\x8B\x41\x04"
#define PARSE_W_UDP_MASK_CSNZ "xxxxxxxxx"

#define PACKET_METADATA_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\xF0\x53\x56\x57\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF1\x8B\x45\x08\x89\x45\x88"
#define PACKET_METADATA_PARSE_MASK_CSNZ "xxxxxx????xx????xxx????x????xxxxxxxxxxxxxx????xxxxxxxx"
#define PACKET_QUEST_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x24\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x8B\xF9\x8B\x45\x08"
#define PACKET_QUEST_PARSE_MASK_CSNZ "xxxxxx????xx????xxxxxxxx????xxxxxxxx????xxxxx"

#define PACKET_HOST_PTR_SIG_CSNZ "\xA1\x00\x00\x00\x00\x6A\x18\x89\x81\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x04\x89\x45\xF0\xC7\x45\x00\x00\x00\x00\x00\x85\xC0\x74\x09\x8B\xC8\xE8\x00\x00\x00\x00\xEB\x02\x33\xC0\x56\x8B\xC8\xC7\x45\x00\x00\x00\x00\x00\xA3\x00\x00\x00\x00\xE8\x00\x00\x00\x00"
#define PACKET_HOST_PTR_MASK_CSNZ "x????xxxx????x????xxxxxxxx?????xxxxxxx????xxxxxxxxx?????x????x????"

#define BOT_MANAGER_PTR_SIG_CSNZ "\xA3\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x83\xC4\x04\x8B\x4D\xF4"
#define BOT_MANAGER_PTR_MASK_CSNZ "x????xx????xxxxxx"

#define SHOWLOGINDLG_SIG_CSNZ "\xA1\x00\x00\x00\x00\x56\x57\x8B\xF9\x8B\x80\x00\x00\x00\x00\xFF\xD0\x8B\xF0\x8B\xCE\x8B\x16\x8B\x52\x24"
#define SHOWLOGINDLG_MASK_CSNZ "x????xxxxxx????xxxxxxxxxxx"

// mov esi, csomainpanel
#define CSOMAINPANEL_PTR_SIG_CSNZ "\x8B\x35\x00\x00\x00\x00\x53\xE8\x00\x00\x00\x00\x83\xC4\x04\x8B\xCF\x56\x50\xFF\xB5\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\xEB\x62"
#define CSOMAINPANEL_PTR_MASK_CSNZ "xx????xx????xxxxxxxxx????x????xxxx"

#define PANEL_FINDCHILDBYNAME_SIG_CSNZ "\x55\x8B\xEC\x83\xEC\x10\x53\x56\x8B\xD9\xC7\x45\x00\x00\x00\x00\x00\x57\x89\x5D\xF8\xE8\x00\x00\x00\x00"
#define PANEL_FINDCHILDBYNAME_MASK_CSNZ "xxxxxxxxxxxx?????xxxxx????"

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT "30002"

extern metahook_api_t gMetaHookAPI;

vgui::IPanel* g_pPanel = nullptr;
vgui::IEngineVGui* g_pEngineVGui = nullptr;
IGameUI* g_pGameUI = nullptr;
CChattingManager* g_pChattingManager;

char g_pServerIP[16];
char g_pServerPort[6];
char g_pLogin[64];
char g_pPassword[64];

bool g_bUseOriginalServer = false;
bool g_bDumpMetadata = false;
bool g_bDumpQuest = false;
bool g_bDisableAuthUI = false;
bool g_bDumpUDP = false;
bool g_bUseSSL = false;
bool g_bWriteMetadata = false;

WNDPROC oWndProc;
HWND hWnd;

vector<string> vectorMetadataName;

void CreateDebugConsole()
{
    AllocConsole();

    freopen( "CONIN$", "r", stdin );
    freopen( "CONOUT$", "w", stdout );
    freopen( "CONOUT$", "w", stderr );

    SetConsoleTitleA("CSO launcher debug console");
    SetConsoleCP( CP_UTF8 );
    SetConsoleOutputCP( CP_UTF8 );
}

void Init(const char* pszGameName)
{
	g_dwEngineBase = 0;
	g_dwEngineSize = 0;
	g_pHookBase = NULL;

	CommandLine()->CreateCmdLine(GetCommandLineA());

	if (CommandLine()->CheckParm("-debug") || CommandLine()->CheckParm("-dev") || CommandLine()->CheckParm("+developer 1") || CommandLine()->CheckParm("-developer"))
		CreateDebugConsole();

	LoadEngine("hw.dll");
}

void *__fastcall SockMgr(void *__this)
{
	void *ptr = g_pfnSocketManagerConstructor(__this);
	char *isSSL = (char*)__this + 0x410;
	*isSSL = g_bUseSSL;
	printf("%d\n", *isSSL);
	printf("0x%X\n", __this);
	return ptr;
}

int __fastcall SocketManager_CSOTW2008(void *__this, int a2, int a3)
{
	return g_pfnSocketManagerCSOTW2008(__this, a2, 1);
}

int __fastcall NexonMessenger(void *_this, int edx, int a2, int a3, int a4)
{
	return 1;
}

int __fastcall ServerConnect(void* _this, int edx, unsigned long ip, short port, int a4)
{
	printf("%d, %d, %d, %d\n", edx, ip, port, a4);
	return g_pfnServerConnect(_this, inet_addr(g_pServerIP), htons(atoi(g_pServerPort)), a4);
}

int NexonMessenger_SGP(void *_this, int edx, int a2)
{
	printf("MH_NEXONMANAGER\n");
	return 1;
}

int GameGuard_Reply()
{
	return 1877;
}

void Pbuf_AddText(const char* text)
{
	g_pEngine->pfnClientCmd((char*)text);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == 0x113 && wParam == 250)
	{
		// handle dropclient msg from anticheat?
		printf("handle_dropclient\n");
		return 0;
	}
	return CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam);
}

int HackShield_UpdateInit()
{
	return 0;
}

int HackShield_DllInit()
{
	return 0;
}

int HackShield_Validate()
{
	return 0;
}

void UnkFunc(int a1, int a2, char *a3)
{
	printf("%d %d %d %d %d\n", a3[0], a3[1], a3[2], a3[3], a3[4]);
	g_pfnUnkFunc(a1, a2, a3);
}

const char* GetMetadataName(int metaDataID)
{
	switch (metaDataID)
	{
	case 0:
		return "MapList.csv";
	case 1:
		return "ClientTable.csv";
	case 2:
		return "ModeList.csv";
	case 9:
		return "GameMatchOption.csv";
	case 17:
		return "WeaponParts.csv";
	case 18:
		return "MileageShop.csv";
	case 24:
		return "GameModeList.csv";
	case 27:
		return "progress_unlock.csv";
	case 28:
		return "ReinforceMaxLv.csv";
	case 29:
		return "ReinforceMaxExp.csv";
	case 32:
		return "Item.csv";
	case 33:
		return "voxel_list.csv";
	case 34:
		return "voxel_item.csv";
	case 36:
		return "HonorMoneyShop.csv";
	case 37:
		return "ItemExpireTime.csv";
	case 38:
		return "scenariotx_common.json";
	case 39:
		return "scenariotx_dedi.json";
	case 40:
		return "shopitemlist_dedi.json";
	case 42:
		return "WeaponProp.json";
	case 45:
		return "ppsystem.json";
	}
	return NULL;
}

HZIP GetMetadataZip(int metaDataID)
{
	switch (metaDataID)
	{
	case 0:
		return MapList_Zip;
	case 1:
		return ClientTable_Zip;
	case 9:
		return GameMatchOption_Zip;
	case 17:
		return WeaponParts_Zip;
	case 18:
		return MileageShop_Zip;
	case 24:
		return GameModeList_Zip;
	case 27:
		return progress_unlock_Zip;
	case 28:
		return ReinforceMaxLv_Zip;
	case 29:
		return ReinforceMaxExp_Zip;
	case 32:
		return Item_Zip;
	case 33:
		return voxel_list_Zip;
	case 34:
		return voxel_item_Zip;
	case 36:
		return HonorMoneyShop_Zip;
	case 37:
		return ItemExpireTime_Zip;
	case 38:
		return scenariotx_common_Zip;
	case 39:
		return scenariotx_dedi_Zip;
	case 40:
		return shopitemlist_dedi_Zip;
	case 42:
		return WeaponProp_Zip;
	case 45:
		return ppsystem_Zip;
	}
	return NULL;
}

int __fastcall Packet_Metadata_Parse(void* _this, int a2, void* packetBuffer, int packetSize)
{
	unsigned char metaDataID = *(unsigned char*)packetBuffer;
	printf("%d\n", metaDataID);

	const char* metaDataName = GetMetadataName(metaDataID);

	if (g_bDumpMetadata)
	{
		char name[128];
		FILE* file = NULL;

		if (metaDataName)
		{
			sprintf(name, "Metadata_%d_%s.bin", metaDataID, metaDataName);
			ifstream file(name);

			if (file.is_open())
			{
				int i = 0;
				bool found = true;
				do
				{
					sprintf(name, "Metadata_%d_%d_%s.bin", metaDataID, i++, metaDataName);
					ifstream file(name);

					found = file.is_open() > 0 ? true : false;
				} while (found);
			}
		}
		else
		{
			sprintf(name, "Metadata_%d.bin", metaDataID);
			ifstream file(name);

			if (file.is_open())
			{
				int i = 0;
				bool found = true;
				do
				{
					sprintf(name, "Metadata_%d_%d.bin", metaDataID, i++);
					ifstream file(name);

					found = file.is_open() > 0 ? true : false;
				} while (found);
			}
		}

		file = fopen(name, "wb");
		fwrite(packetBuffer, packetSize, 1, file);
		fclose(file);
	}

	if (g_bWriteMetadata)
	{
		if(metaDataName != NULL && std::find(vectorMetadataName.begin(), vectorMetadataName.end(), metaDataName) != vectorMetadataName.end())
		{
			HZIP MetaDataZip = GetMetadataZip(metaDataID);

			MetaDataZip = CreateZip(0, MAX_ZIP_SIZE, ZIP_MEMORY);

			if (!MetaDataZip)
				printf("CreateZip returned NULL.\n");

			char path[128];
			sprintf(path, "Metadata/%s", metaDataName);
			cout << path << endl;
			void* metadataName = path;

			if (ZipAdd(MetaDataZip, metaDataName, metadataName, 0, ZIP_FILENAME))
				printf("ZipAdd returned error.\n");

			void* buffer;
			unsigned long length = 0;
			ZipGetMemory(MetaDataZip, &buffer, &length);

			const char* charBuffer = (char*)buffer;
			vector<char> vectorBuffer(charBuffer, charBuffer + length);

			unsigned char length1 = length;
			unsigned char length2 = length >> 8;

			vectorBuffer.insert(vectorBuffer.begin(), length2);
			vectorBuffer.insert(vectorBuffer.begin(), length1);
			vectorBuffer.insert(vectorBuffer.begin(), metaDataID);

			CloseZip(MetaDataZip);

			return g_pfnPacket_Metadata_Parse(_this, static_cast<void*>(vectorBuffer.data()), length + 3);
		}
	}

	return g_pfnPacket_Metadata_Parse(_this, packetBuffer, packetSize);
}
	
bool __fastcall Packet_Quest_Parse(void* _this, int a2, void* packetBuffer, int packetSize)
{
	char subType = *(char*)packetBuffer;
	printf("%d\n", subType);

	char name[128];
	sprintf(name, "Quest_%d.bin", subType);

	FILE *file = fopen(name, "wb");
	fwrite(packetBuffer, packetSize, 1, file);
	fclose(file);

	return g_pfnPacket_Quest_Parse(_this, packetBuffer, packetSize);
}

class Packet
{
public:
	int unk;
	void* ptr;
	void* ptr2;
	int unk1;
	int unk2;
	int unk3;
	int unk4;
};

bool __fastcall Packet_Host_Parse(Packet* _this, int a2, void* packetBuffer, int packetSize)
{
	char subType = *(char*)packetBuffer;
	printf("%d\n", subType);
	if (subType == 1 || subType == 5)
	{
		// replace packet buffer with our modified
		return false;
	}

	return g_pfnPacket_Host_Parse(_this, packetBuffer, packetSize);
}

void __fastcall LoginDlg_OnCommand(void* _this, int r, const char* command)
{
	if (!strcmp(command, "Login"))
	{
		DWORD** v3 = (DWORD**)_this;
		char login[256];
		char password[256];
		
		//void* pLoginTextEntry = g_pfnPanel_FindChildByName(_this, "1");
		//void* pPasswordTextEntry = g_pfnPanel_FindChildByName(_this, "1");
		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[109] + 620))(v3[109], login, 256); // textentry->GetText()
		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[110] + 620))(v3[110], password, 256);

		wchar_t buf[256];
		swprintf(buf, L"/login %S %S", login, password);
		g_pChattingManager->PrintToChat(1, buf);
		return;
	}
	else if (!strcmp(command, "Register"))
	{
		DWORD** v3 = (DWORD**)_this;
		char login[256];
		char password[256];

		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[109] + 620))(v3[109], login, 256); // textentry->GetText()
		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[110] + 620))(v3[110], password, 256);

		wchar_t buf[256];
		swprintf(buf, L"/register %S %S", login, password);
		g_pChattingManager->PrintToChat(1, buf);
		return;
	}

	g_pfnLoginDlg_OnCommand(_this, command);
}

bool bShowLoginDlg = false;
int __fastcall GameUI_RunFrame(void* _this)
{
	if (!bShowLoginDlg)
	{
		if (strlen(g_pLogin) != 0 || strlen(g_pPassword) != 0)
		{
			wchar_t buf[256];
			swprintf(buf, L"/login %S %S", g_pLogin, g_pPassword);
			g_pChattingManager->PrintToChat(1, buf);
		}

		if (!g_bDisableAuthUI)
		{
			__try
			{
				g_pCSOMainPanel = **((void***)(FindPattern(CSOMAINPANEL_PTR_SIG_CSNZ, CSOMAINPANEL_PTR_MASK_CSNZ, g_dwGameUIBase, g_dwGameUIBase + g_dwGameUISize, 2)));
				if (!g_pCSOMainPanel)
				{
					MessageBox(NULL, "g_pCSOMainPanel == NULL!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
					bShowLoginDlg = true;
					return g_pfnGameUI_RunFrame(_this);
				}

				void* pLoginDlg = *(void**)((DWORD)g_pCSOMainPanel + 364);
				VFTHook(pLoginDlg, 0, 98, LoginDlg_OnCommand, (void*&)g_pfnLoginDlg_OnCommand);

				if (!g_pfnPanel_FindChildByName)
				{
					MessageBox(NULL, "g_pfnPanel_FindChildByName == NULL!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
					bShowLoginDlg = true;
					return g_pfnGameUI_RunFrame(_this);
				}

				void* pRegisterBtn = g_pfnPanel_FindChildByName(pLoginDlg, "RegisterBtn", false);
				void* pFindIDBtn = g_pfnPanel_FindChildByName(pLoginDlg, "FindIDBtn", false);
				void* pFindPWBtn = g_pfnPanel_FindChildByName(pLoginDlg, "FindPWBtn", false);
				void* pImagePanel1 = g_pfnPanel_FindChildByName(pLoginDlg, "ImagePanel1", false);

				if (!pRegisterBtn || !pFindIDBtn || !pFindPWBtn || !pImagePanel1)
				{
					MessageBox(NULL, "Invalid ptrs!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
					bShowLoginDlg = true;
					return g_pfnGameUI_RunFrame(_this);
				}

				void* v27 = (**(void* (__thiscall***)(void*))pRegisterBtn)(pRegisterBtn);
				g_pPanel->SetPos((vgui::IPanel*)v27, 50, 141);
				//(*(void(__stdcall**)(void*, int, int))(*(DWORD*)pRegisterBtn + 4))(pRegisterBtn, 50, 141); // button->SetPos()
				(*(void(__thiscall**)(void*, bool))(*(DWORD*)pFindIDBtn + 160))(pFindIDBtn, false); // button->SetVisible()
				(*(void(__thiscall**)(void*, bool))(*(DWORD*)pFindPWBtn + 160))(pFindPWBtn, false); // button->SetVisible()
				(*(void(__thiscall**)(void*, const char*))(*(DWORD*)pRegisterBtn + 604))(pRegisterBtn, "Register"); // button->SetText()
				//(*(void(__thiscall**)(void*, const char*))(*(DWORD*)pImagePanel1 + 600))(pImagePanel1, "resource/login.tga"); // imagepanel->SetImage()
				(*(void(__thiscall**)(void*))(*(DWORD*)pLoginDlg + 832))(pLoginDlg); // loginDlg->DoModal()

				// i lost fucking g_pfnShowLoginDlg reference...
				/*if (g_pfnShowLoginDlg)
				{
					g_pfnShowLoginDlg(g_pCSOMainPanel);
				}
				else
				{
					MessageBox(NULL, "g_pfnShowLoginDlg == NULL!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
				}*/
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				MessageBox(NULL, "Something went wrong while initializing the Auth UI!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
			}
		}
		bShowLoginDlg = true;
	}
	return g_pfnGameUI_RunFrame(_this);
}

void CSO_Bot_Add()
{
	// get current botmgr ptr
	DWORD dwBotManagerPtr = FindPattern(BOT_MANAGER_PTR_SIG_CSNZ, BOT_MANAGER_PTR_MASK_CSNZ, g_dwMpBase, g_dwMpBase + g_dwMpSize, 1);
	g_pBotManager = **((CCSBotManager***)(dwBotManagerPtr));

	if (!g_pBotManager)
	{
		g_pEngine->Con_Printf("CSO_Bot_Add: g_pBotManager == NULL\n");
		return;
	}
	int arg1 = 0, arg2 = 0;
	int argc = g_pEngine->Cmd_Argc();
	if (argc > 0)
	{	
		arg1 = atoi(g_pEngine->Cmd_Argv(1));
		if (argc >= 2)
		{
			arg2 = atoi(g_pEngine->Cmd_Argv(2));
		}
	}
	g_pBotManager->Bot_Add(arg1);
}

void CSOTW_2009_InitHooks()
{
	/*g_pHackShield_UpdateInit = (void*)FindPattern(HACKSHIELD_UPDATEINIT_SIG_CSOTW2009, HACKSHIELD_UPDATEINIT_MASK_CSOTW2009, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	g_phHackShield_UpdateInit = InlineHook(g_pHackShield_UpdateInit, HackShield_UpdateInit, (void*&)g_pfnHackShield_UpdateInit);
	printf("g_pHackShield_UpdateInit: 0x%x\n", g_pHackShield_UpdateInit);

	g_pHackShield_DllInit = (void*)FindPattern(HACKSHIELD_DLLINIT_SIG_CSOTW2009, HACKSHIELD_DLLINIT_MASK_CSOTW2009, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	g_phHackShield_DllInit = InlineHook(g_pHackShield_DllInit, HackShield_DllInit, (void*&)g_pfnHackShield_DllInit);
	printf("g_pHackShield_DllInit: 0x%x\n", g_pHackShield_DllInit);

	g_pHackShield_Validate = (void*)FindPattern(HACKSHIELD_VALIDATE_SIG_CSOTW2009, HACKSHIELD_VALIDATE_MASK_CSOTW2009, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	g_phHackShield_Validate = InlineHook(g_pHackShield_Validate, HackShield_Validate, (void*&)g_pfnHackShield_Validate);
	printf("g_pHackShield_Validate: 0x%x\n", g_pHackShield_Validate);*/

	g_pUnkFunc2 = (void*)FindPattern(UNK2_SIG_CSOTW2009, UNK2_MASK_CSOTW2009, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);;
	g_phUnkFunc2 = InlineHook(g_pUnkFunc2, UnkFunc, (void*&)g_pfnUnkFunc2);

	printf("CSOTW_2009_InitHooks: 0x%x\n", g_pUnkFunc);
}

int packetCounter = 0;
int WINAPI h_Recvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
	int readlen = g_pfnRecvfrom(s, buf, len, flags, from, fromlen);
	
	if (readlen > 0)
	{
		sockaddr_in* in = (sockaddr_in*)from;
		char ipAddress[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &in->sin_addr, ipAddress, INET_ADDRSTRLEN);

		printf("Recvfrom: ip: %s, port: %d, data: ", ipAddress, in->sin_port);

		for (int i = 0; i < readlen; i++)
		{
			printf("%X ", buf[i]);
		}
		printf("\n");
		//char name[128];
		//sprintf(name, "Recvfrom_%d.bin", packetCounter++);

		//FILE* file = fopen(name, "wb");
		//fwrite(buf, readlen, 1, file);
		//fclose(file);
	}

	return readlen;
}

int WINAPI h_Sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
	sockaddr_in* in = (sockaddr_in*)to;
	char ipAddress[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &in->sin_addr, ipAddress, INET_ADDRSTRLEN);

	printf("Sendto: ip: %s, port: %d, data: ", ipAddress, in->sin_port);

	for (int i = 0; i < len; i++)
	{
		printf("%X ", buf[i]);
	}
	printf("\n");

	//char name[128];
	//sprintf(name, "Sendto_%d.bin", packetCounter++);

	//FILE* file = fopen(name, "wb");
	//fwrite(buf, len, 1, file);
	//fclose(file);

	return g_pfnSendto(s, buf, len, flags, to, tolen);
}

void CSNZ_InitHooks()
{
	printf("Hook()\n");

	// temp
#if 0
	{
		HMODULE hSSL = GetModuleHandle("LIBEAY32.dll");
		if (hSSL)
		{
			auto decUpd = GetProcAddress(hSSL, "EVP_DecryptUpdate");

			g_phEVP_DecryptUpdate = InlineHook(decUpd, hkEVP_DecryptUpdate, (void*&)g_pfnEVP_DecryptUpdate);
		}
	}
#endif
	if (g_bDumpUDP)
	{
		InlineHook(GetProcAddress(GetModuleHandleA("WSOCK32.dll"), "recvfrom"), h_Recvfrom, (void*&)g_pfnRecvfrom);
		InlineHook(GetProcAddress(GetModuleHandleA("WSOCK32.dll"), "sendto"), h_Sendto, (void*&)g_pfnSendto);
	}

	g_pSocketManagerConstructor = (void*)FindPattern(SOCKETMANAGER_SIG_CSNZ19, SOCKETMANAGER_MASK_CSNZ19, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!g_bUseOriginalServer)
	{
		if (!g_pSocketManagerConstructor)
			MessageBox(NULL, "g_pSocketManagerConstructor == NULL!!!", "Error", MB_OK);

		g_phSocketManagerConstructor = InlineHook(g_pSocketManagerConstructor, SockMgr, (void*&)g_pfnSocketManagerConstructor);
	}

	printf("0x%X\n", g_pSocketManagerConstructor);

	g_pServerConnect = (void*)FindPattern(SERVERCONNECT_SIG_CSNZ2019, SERVERCONNECT_MASK_CSNZ2019, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!g_bUseOriginalServer)
	{
		if (!g_pServerConnect)
			MessageBox(NULL, "g_pServerConnect == NULL!!!", "Error", MB_OK);

		g_phServerConnect = InlineHook(g_pServerConnect, ServerConnect, (void*&)g_pfnServerConnect);
	}

	printf("0x%X\n", g_pServerConnect);

	//g_pUnkFunc = (void*)FindPattern(PARSE_W_UDP_SIG_CSNZ, PARSE_W_UDP_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	//g_phUnkFunc = InlineHook(g_pUnkFunc, UnkFunc, (void*&)g_pfnUnkFunc);

	//printf("0x%X\n", g_pUnkFunc);

	g_pEngine = (cl_enginefunc_t*)(PVOID) * (PDWORD)(FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("ScreenFade")) + 0x0D);
	if (!g_pEngine)
		MessageBox(NULL, "g_pEngine == NULL!!!", "Error", MB_OK);

	// hook Pbuf_AddText to allow any cvar or cmd input
	g_pEngine->Pbuf_AddText = Pbuf_AddText;

	DWORD dwClientBase = 0;
	while (!dwClientBase) // wait for the client.dll module to hook Pbuf_AddText before cl_enginefunc_s struct is passed to the GameUI.dll module
	{
		dwClientBase = (DWORD)GetModuleHandle("client.dll");
		Sleep(1);
	}

	while (!g_dwGameUIBase) // wait for gameui module
	{
		g_dwGameUIBase = (DWORD)GetModuleHandle("gameui.dll");
		Sleep(1);
	}

	g_dwGameUISize = GetModuleSize(GetModuleHandle("gameui.dll"));

	hWnd = FindWindow(NULL, "Counter-Strike Nexon: Studio");
	oWndProc = (WNDPROC)SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)WndProc);

	g_pChattingManager = g_pEngine->GetChatManager();
	if (!g_pChattingManager)
		MessageBox(NULL, "g_pChattingManager == NULL!!!", "Error", MB_OK);

	printf("0x%X\n", g_pEngine);
	printf("0x%X\n", g_pChattingManager);

	g_pfnShowLoginDlg = (tShowLoginDlg)FindPattern(SHOWLOGINDLG_SIG_CSNZ, SHOWLOGINDLG_MASK_CSNZ, g_dwGameUIBase, g_dwGameUIBase + g_dwGameUISize, -0xB0);
	g_pfnPanel_FindChildByName = (tPanel_FindChildByName)FindPattern(PANEL_FINDCHILDBYNAME_SIG_CSNZ, PANEL_FINDCHILDBYNAME_MASK_CSNZ, g_dwGameUIBase, g_dwGameUIBase + g_dwGameUISize, 0);
	
	printf("0x%X\n", g_pfnShowLoginDlg);
	printf("0x%X\n", g_pfnPanel_FindChildByName);

	CreateInterfaceFn gameui_factory = CaptureFactory("gameui.dll");
	CreateInterfaceFn vgui2_factory = CaptureFactory("vgui2.dll");
	g_pGameUI = (IGameUI*)(CaptureInterface(gameui_factory, GAMEUI_INTERFACE_VERSION));
	g_pPanel = (vgui::IPanel*)(CaptureInterface(vgui2_factory, VGUI_PANEL_INTERFACE_VERSION));
	VFTHook(g_pGameUI, 0, 7, GameUI_RunFrame, (void*&)g_pfnGameUI_RunFrame);

	// unused
	/*g_pGameConsoleInput = (void*)FindPattern(GAMECONSOLEINPUT_SIG_CSNZ19, GAMECONSOLEINPUT_MASK_CSNZ19, g_dwGameUIBase, g_dwGameUIBase + g_dwGameUISize, NULL);
	if (!g_pGameConsoleInput)
	{
		MessageBox(NULL, "g_pGameConsoleInput == NULL!!!", "Error", MB_OK);
	}
	g_phGameConsoleInput = InlineHook(g_pGameConsoleInput, H_AddToHistory, (void*&)g_pfnGameConsoleInput);
	printf("0x%X\n", g_pGameConsoleInput);*/

	while (!g_dwMpBase) // wait for mp.dll module
	{
		g_dwMpBase = (DWORD)GetModuleHandle("mp.dll");
		Sleep(1000);
	}
	g_dwMpSize = GetModuleSize(GetModuleHandle("mp.dll"));

	g_pEngine->pfnAddCommand("cso_bot_add", CSO_Bot_Add);

	g_pPacket_Metadata_Parse = (void*)FindPattern(PACKET_METADATA_PARSE_SIG_CSNZ, PACKET_METADATA_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (g_bDumpMetadata || g_bWriteMetadata)
	{
		if (!g_pPacket_Metadata_Parse)
			MessageBox(NULL, "g_pPacket_Metadata_Parse == NULL!!!", "Error", MB_OK);

		if (g_bWriteMetadata)
		{
			std::filesystem::path path = std::filesystem::current_path() / "Metadata";
			struct dirent* entry;
			DIR* dir = opendir(path.string().c_str());

			if (dir == NULL) {
				printf("Bin/Metadata directory not found.\n");
				g_bWriteMetadata = false;
			}

			if (g_bWriteMetadata)
			{
				while ((entry = readdir(dir)) != NULL) {
					vectorMetadataName.push_back(entry->d_name);
				}
				closedir(dir);
			}
		}

		if (g_bDumpMetadata || g_bWriteMetadata)
			g_phPacket_Metadata_Parse = InlineHook(g_pPacket_Metadata_Parse, Packet_Metadata_Parse, (void*&)g_pfnPacket_Metadata_Parse);
	}
	printf("0x%X\n", g_pPacket_Metadata_Parse);

	g_pPacket_Quest_Parse = (void*)FindPattern(PACKET_QUEST_PARSE_SIG_CSNZ, PACKET_QUEST_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (g_bDumpQuest)
	{
		if (!g_pPacket_Quest_Parse)
			MessageBox(NULL, "g_pPacket_Quest_Parse == NULL!!!", "Error", MB_OK);

		g_phPacket_Quest_Parse = InlineHook(g_pPacket_Quest_Parse, Packet_Quest_Parse, (void*&)g_pfnPacket_Quest_Parse);
	}
	printf("0x%X\n", g_pPacket_Quest_Parse);

	g_pPacket_Host = **((void***)(FindPattern(PACKET_HOST_PTR_SIG_CSNZ, PACKET_HOST_PTR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, 1)));
	if (g_bDumpQuest)
	{
		if (!g_pPacket_Host)
			MessageBox(NULL, "g_pPacket_Host == NULL!!!", "Error", MB_OK);

		//VFTHook(g_pPacket_Host, 0, 2, Packet_Host_Parse, (void*&)g_pfnPacket_Host_Parse);
	}
	printf("0x%X\n", g_pPacket_Host);
}

void LoadEngine(const char* pszEngineName)
{
	printf("Init()\n");

	if (pszEngineName)
	{
		while (!g_hEngineModule)
		{
			g_hEngineModule = GetModuleHandleA(pszEngineName);
			Sleep(1);
		}

		g_dwEngineBase = GetModuleBase(g_hEngineModule);
		g_dwEngineSize = GetModuleSize(g_hEngineModule);
	}

	printf("%s\n", CommandLine()->GetCmdLine());

	const char* port;
	const char* ip;

	if (CommandLine()->CheckParm("-ip", &ip) && ip)
	{
		strncpy(g_pServerIP, ip, sizeof(g_pServerIP));
	}
	else
	{
		strncpy(g_pServerIP, DEFAULT_IP, sizeof(DEFAULT_IP));
	}

	if (CommandLine()->CheckParm("-port", &port) && port)
	{
		strncpy(g_pServerPort, port, sizeof(g_pServerPort));
	}
	else
	{
		strncpy(g_pServerPort, DEFAULT_PORT, sizeof(DEFAULT_PORT));
	}

	const char* login;
	const char* password;

	if (CommandLine()->CheckParm("-login", &login) && login)
	{
		strncpy(g_pLogin, login, sizeof(g_pLogin));
	}
	if (CommandLine()->CheckParm("-password", &password) && password)
	{
		strncpy(g_pPassword, password, sizeof(g_pPassword));
	}

	g_bUseOriginalServer = CommandLine()->CheckParm("-useoriginalserver");
	g_bDumpMetadata = CommandLine()->CheckParm("-dumpmetadata");
	g_bDumpQuest = CommandLine()->CheckParm("-dumpquest");
	g_bDisableAuthUI = CommandLine()->CheckParm("-disableauthui");
	g_bDumpUDP = CommandLine()->CheckParm("-dumpudp");
	g_bUseSSL = CommandLine()->CheckParm("-usessl");
	g_bWriteMetadata = CommandLine()->CheckParm("-writemetadata");

	/*int argc = 0;
	char** argv = CommandLineToArgvA(GetCommandLineA(), &argc);
	printf("argc = %d\n", argc);
	for (int i = 0; i < argc; i++)
	{
		printf("%s\n", argv[i]);
	}

	if (argv[0][0] == '-' && argv[0][2] == 'p')
	{
		if (!strcmp(argv[0], "-ip"))
		{
			g_pServerIP = argv[1];
		}
		else
		{
			g_pServerIP = DEFAULT_IP;
		}

		if (!strcmp(argv[2], "-port"))
		{
			g_pServerPort = argv[3];
		}
		else
		{
			g_pServerPort = DEFAULT_PORT;
		}
	}
	else if (argc >= 5)
	{
		if (!strcmp(argv[1], "-ip"))
		{
			g_pServerIP = argv[2];
		}
		else
		{
			g_pServerIP = DEFAULT_IP;
		}

		if (!strcmp(argv[3], "-port"))
		{
			g_pServerPort = argv[4];
		}
		else
		{
			g_pServerPort = DEFAULT_PORT;
		}
	}
	else
	{
		g_pServerIP = DEFAULT_IP;
		g_pServerPort = DEFAULT_PORT;
	}*/

	printf("g_pLogin = %s, g_pPassword = %s\n", g_pLogin, g_pPassword);
	printf("g_pServerIP = %s, g_pServerPort = %s\n", g_pServerIP, g_pServerPort);

	switch (0)
	{
	case 0:
		CSNZ_InitHooks();
		break;
	case 1:
		CSOTW_2009_InitHooks();
		break;
	};

	/*if(csoSGP)
	{
		g_pSocketManagerConstructor = (void *)MH_FindPattern(SOCKETMANAGER_SIG_CSOSGP, SOCKETMANAGER_MASK_CSOSGP, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		g_phSocketManagerConstructor = MH_InlineHook(g_pSocketManagerConstructor, MH_SockMgr, (void *&)g_pfnSocketManagerConstructor);
	}
	else
	{
		g_pSocketManagerConstructor = MH_SearchPattern((void *)g_dwEngineBase, g_dwEngineSize, SOCKETMANAGER_SIG_CSNZ15, sizeof(SOCKETMANAGER_SIG_CSNZ15) - 1);
		g_phSocketManagerConstructor = MH_InlineHook(g_pSocketManagerConstructor, MH_SockMgr, (void *&)g_pfnSocketManagerConstructor);
	}

	if(csoSGP)
	{
		g_pPacketRead = (void *)MH_FindPattern(NEXONMANAGER_SIG_CSOSGP, NEXONMANAGER_MASK_CSOSGP, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		g_phPacketRead = MH_InlineHook(g_pPacketRead, MH_NexonMessenger, (void *&)g_pfnPacketRead);
	}
	else
	{
		g_pPacketRead = (void *)MH_FindPattern(NEXONMANAGER_SIG_CSOIDN16, NEXONMANAGER_MASK_CSOIDN16, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		g_phPacketRead = MH_InlineHook(g_pPacketRead, MH_NexonMessenger, (void *&)g_pfnPacketRead);
		
		g_pPacket_RoomList = (void *)MH_FindPattern(PACKET_ROOMLIST_SIG_CSNZ15, PACKET_ROOMLIST_MASK_CSNZ15, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		g_phPacket_RoomList = MH_InlineHook(g_pPacket_RoomList, Packet_RoomList, (void *&)g_pfnPacket_RoomList);
	}*/

	// cso sgp
	//g_pSocketManagerConstructor = (void *)MH_FindPattern(SOCKETMANAGER_SIG_CSOSGP, SOCKETMANAGER_MASK_CSOSGP, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	//g_phSocketManagerConstructor = MH_InlineHook(g_pSocketManagerConstructor, MH_SockMgr, (void *&)g_pfnSocketManagerConstructor);
	//g_pPacketRead = (void *)MH_FindPattern(NEXONMANAGER_SIG_CSOSGP, NEXONMANAGER_MASK_CSOSGP, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	//g_phPacketRead = MH_InlineHook(g_pPacketRead, MH_NexonMessenger, (void *&)g_pfnPacketRead);

	//printf("SSL: 0x%X\n", g_pSocketManagerConstructor);
	//printf("NexonMessenger: 0x%X\n", g_pPacketRead);

	// cso tw
	/*g_pGameGuard_Init = (void *)MH_FindPattern(GAMEGUARD_REPLY_SIG_CSOTW2008, GAMEGUARD_REPLY_MASK_CSOTW2008, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	g_phGameGuard_Init = MH_InlineHook(g_pGameGuard_Init, GameGuard_Reply, (void *&)g_pfnGameGuard_Init);
	
	g_pSocketManagerCSOTW2008 = (void *)MH_FindPattern(SOCKETMANAGER_SIG_CSOTW2008, SOCKETMANAGER_MASK_CSOTW2008, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	g_phSocketManagerCSOTW2008 = MH_InlineHook(g_pSocketManagerCSOTW2008, SocketManager_CSOTW2008, (void *&)g_pfnSocketManagerCSOTW2008);

	printf("SSL: 0x%X\n", g_pGameGuard_Init);
	printf("NexonMessenger: 0x%X\n", g_pPacketRead);*/
}

hook_t *NewHook(void)
{
	hook_t *h = new hook_t;
	memset(h, 0, sizeof(hook_t));
	h->pNext = g_pHookBase;
	g_pHookBase = h;
	return h;
}

hook_t *FindInlineHooked(void *pOldFuncAddr)
{
	for (hook_t *h = g_pHookBase; h; h = h->pNext)
	{
		if (h->pOldFuncAddr == pOldFuncAddr)
			return h;
	}

	return NULL;
}

hook_t *FindVFTHooked(void *pClass, int iTableIndex, int iFuncIndex)
{
	for (hook_t *h = g_pHookBase; h; h = h->pNext)
	{
		if (h->pClass == pClass && h->iTableIndex == iTableIndex && h->iFuncIndex == iFuncIndex)
			return h;
	}

	return NULL;
}

hook_t *FindIATHooked(HMODULE hModule, const char *pszModuleName, const char *pszFuncName)
{
	for (hook_t *h = g_pHookBase; h; h = h->pNext)
	{
		if (h->hModule == hModule && h->pszModuleName == pszModuleName && h->pszFuncName == pszFuncName)
			return h;
	}

	return NULL;
}

#pragma pack(push, 1)

struct tagIATDATA
{
	void *pAPIInfoAddr;
};

struct tagCLASS
{
	DWORD *pVMT;
};

struct tagVTABLEDATA
{
	tagCLASS *pInstance;
	void *pVFTInfoAddr;
};

#pragma pack(pop)

void FreeHook(hook_t *pHook)
{
	if (pHook->pClass)
	{
		tagVTABLEDATA *info = (tagVTABLEDATA *)pHook->pInfo;
		WriteMemory(info->pVFTInfoAddr, (BYTE *)pHook->pOldFuncAddr, sizeof(DWORD));
	}
	else if (pHook->hModule)
	{
		tagIATDATA *info = (tagIATDATA *)pHook->pInfo;
		WriteMemory(info->pAPIInfoAddr, (BYTE *)pHook->pOldFuncAddr, sizeof(DWORD));
	}
	else
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(void *&)pHook->pOldFuncAddr, pHook->pNewFuncAddr);
		DetourTransactionCommit();
	}

	if (pHook->pInfo)
		delete pHook->pInfo;

	delete pHook;
}

void FreeAllHook(void)
{
	hook_t *next = NULL;

	for (hook_t *h = g_pHookBase; h; h = next)
	{
		next = h->pNext;
		FreeHook(h);
	}

	g_pHookBase = NULL;
}

BOOL UnHook(hook_t *pHook)
{
	if (!g_pHookBase)
		return FALSE;

	if (!g_pHookBase->pNext)
	{
		FreeHook(pHook);
		g_pHookBase = NULL;
		return TRUE;
	}

	hook_t *last = NULL;

	for (hook_t *h = g_pHookBase->pNext; h; h = h->pNext)
	{
		if (h->pNext != pHook)
		{
			last = h;
			continue;
		}

		last->pNext = h->pNext;
		FreeHook(h);
		return TRUE;
	}

	return FALSE;
}

hook_t *InlineHook(void *pOldFuncAddr, void *pNewFuncAddr, void *&pCallBackFuncAddr)
{
	hook_t *h = NewHook();
	h->pOldFuncAddr = pOldFuncAddr;
	h->pNewFuncAddr = pNewFuncAddr;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(void *&)h->pOldFuncAddr, pNewFuncAddr);
	DetourTransactionCommit();

	pCallBackFuncAddr = h->pOldFuncAddr; 
	return h;
}

hook_t *VFTHook(void *pClass, int iTableIndex, int iFuncIndex, void *pNewFuncAddr, void *&pCallBackFuncAddr)
{
	tagVTABLEDATA *info = new tagVTABLEDATA;
	info->pInstance = (tagCLASS *)pClass;

	DWORD *pVMT = ((tagCLASS *)pClass + iTableIndex)->pVMT;
	info->pVFTInfoAddr = pVMT + iFuncIndex;

	hook_t *h = NewHook();
	h->pOldFuncAddr = (void *)pVMT[iFuncIndex];
	h->pNewFuncAddr = pNewFuncAddr;
	h->pInfo = info;
	h->pClass = pClass;
	h->iTableIndex = iTableIndex;
	h->iFuncIndex = iFuncIndex;

	pCallBackFuncAddr = h->pOldFuncAddr;
	WriteMemory(info->pVFTInfoAddr, (BYTE *)&pNewFuncAddr, sizeof(DWORD));
	return 0;
}

hook_t *IATHook(HMODULE hModule, const char *pszModuleName, const char *pszFuncName, void *pNewFuncAddr, void *&pCallBackFuncAddr)
{
	IMAGE_NT_HEADERS *pHeader = (IMAGE_NT_HEADERS *)((DWORD)hModule + ((IMAGE_DOS_HEADER *)hModule)->e_lfanew);
	IMAGE_IMPORT_DESCRIPTOR *pImport = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)hModule + pHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImport->Name && stricmp((const char *)((DWORD)hModule + pImport->Name), pszModuleName))
		pImport++;

	DWORD dwFuncAddr = (DWORD)GetProcAddress(GetModuleHandle(pszModuleName), pszFuncName);
	IMAGE_THUNK_DATA *pThunk = (IMAGE_THUNK_DATA *)((DWORD)hModule + pImport->FirstThunk);

	while (pThunk->u1.Function != dwFuncAddr)
		pThunk++;

	tagIATDATA *info = new tagIATDATA;
	info->pAPIInfoAddr = &pThunk->u1.Function;

	hook_t *h = NewHook();
	h->pOldFuncAddr = (void *)pThunk->u1.Function;
	h->pNewFuncAddr = pNewFuncAddr;
	h->pInfo = info;
	h->hModule = hModule;
	h->pszModuleName = pszModuleName;
	h->pszFuncName = pszFuncName;

	pCallBackFuncAddr = h->pOldFuncAddr;
	WriteMemory(info->pAPIInfoAddr, (BYTE *)&pNewFuncAddr, sizeof(DWORD));
	return h;
}

void *GetClassFuncAddr(...)
{
	DWORD address;

	__asm
	{
		lea eax,address
		mov edx, [ebp + 8]
		mov [eax], edx
	}

	return (void *)address;
}

DWORD GetModuleBase(HMODULE hModule)
{
	MEMORY_BASIC_INFORMATION mem;

	if (!VirtualQuery(hModule, &mem, sizeof(MEMORY_BASIC_INFORMATION)))
		return 0;

	return (DWORD)mem.AllocationBase;
}

DWORD GetModuleSize(HMODULE hModule)
{
	return ((IMAGE_NT_HEADERS *)((DWORD)hModule + ((IMAGE_DOS_HEADER *)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
}

HMODULE GetEngineModule(void)
{
	return g_hEngineModule;
}

DWORD GetEngineBase(void)
{
	return g_dwEngineBase;
}

DWORD GetEngineSize(void)
{
	return g_dwEngineSize;
}

DWORD FindPattern(PCHAR pattern, PCHAR mask, DWORD start, DWORD end, DWORD offset)
{
	int patternLength = strlen(mask);
	bool found = false;

	for (DWORD i = start; i < end - patternLength; i++)
	{
		found = true;
		for (int idx = 0; idx < patternLength; idx++)
		{
			if (mask[idx] == 'x' && pattern[idx] != *(PCHAR)(i + idx))
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			return i + offset;
		}
	}

	return 0;
}

DWORD FindPattern(PCHAR pattern, DWORD start, DWORD end, DWORD offset)
{
	size_t patternLength = strlen(pattern);
	bool found = false;

	for (DWORD i = start; i < end - patternLength; i++)
	{
		found = true;

		for (size_t idx = 0; idx < patternLength; idx++)
		{
			if (pattern[idx] != *(PCHAR)(i + idx))
			{
				found = false;
				break;
			}
		}

		if (found)
			return i + offset;
	}

	return 0;
}

DWORD FindPush(DWORD start, DWORD end, PCHAR Message)
{
	char bPushAddrPattern[] = { 0x68 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 };
	DWORD Address = FindPattern(Message, start, end, 0);
	*(PDWORD)&bPushAddrPattern[1] = Address;
	Address = FindPattern((PCHAR)bPushAddrPattern, start, end, 0);
	return Address;
}

void *SearchPattern(void *pStartSearch, DWORD dwSearchLen, char *pPattern, DWORD dwPatternLen)
{
	DWORD dwStartAddr = (DWORD)pStartSearch;
	DWORD dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen;

	while (dwStartAddr < dwEndAddr)
	{
		bool found = true;

		for (int i = 0; i < dwPatternLen; i++)
		{
			char code = *(char *)(dwStartAddr + i);

			if (pPattern[i] != 0x2A && pPattern[i] != code)
			{
				found = false;
				break;
			}
		}

		if (found)
			return (void *)dwStartAddr;

		dwStartAddr++;
	}

	return 0;
}

void WriteDWORD(void *pAddress, DWORD dwValue)
{
	DWORD dwProtect;

	if (VirtualProtect((void *)pAddress, 4, PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		*(DWORD *)pAddress = dwValue;
		VirtualProtect((void *)pAddress, 4, dwProtect, &dwProtect);
	}
}

DWORD ReadDWORD(void *pAddress)
{
	DWORD dwProtect;
	DWORD dwValue = 0;

	if (VirtualProtect((void *)pAddress, 4, PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		dwValue = *(DWORD *)pAddress;
		VirtualProtect((void *)pAddress, 4, dwProtect, &dwProtect);
	}

	return dwValue;
}

DWORD WriteMemory(void *pAddress, BYTE *pData, DWORD dwDataSize)
{
	static DWORD dwProtect;

	if (VirtualProtect(pAddress, dwDataSize, PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		memcpy(pAddress, pData, dwDataSize);
		VirtualProtect(pAddress, dwDataSize, dwProtect, &dwProtect);
	}

	return dwDataSize;
}

DWORD ReadMemory(void *pAddress, BYTE *pData, DWORD dwDataSize)
{
	static DWORD dwProtect;

	if (VirtualProtect(pAddress, dwDataSize, PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		memcpy(pData, pAddress, dwDataSize);
		VirtualProtect(pAddress, dwDataSize, dwProtect, &dwProtect);
	}

	return dwDataSize;
}

DWORD GetVideoMode(int *width, int *height, int *bpp, bool *windowed)
{
	static int iSaveMode;
	static int iSaveWidth, iSaveHeight, iSaveBPP;
	static bool bSaveWindowed;

	/*if (g_bSaveVideo)
	{
		if (width)
			*width = iSaveWidth;

		if (height)
			*height = iSaveHeight;

		if (bpp)
			*bpp = iSaveBPP;

		if (windowed)
			*windowed = bSaveWindowed;
	}
	else
	{
		const char *pszValues = registry->ReadString("EngineDLL", "hw.dll");
		int iEngineD3D = registry->ReadInt("EngineD3D");

		if (!strcmp(pszValues, "hw.dll"))
		{
			if (iEngineD3D || CommandLine()->CheckParm("-d3d"))
				iSaveMode = VIDEOMODE_D3D;
			else
				iSaveMode = VIDEOMODE_OPENGL;
		}
		else
			iSaveMode = VIDEOMODE_SOFTWARE;

		bSaveWindowed = registry->ReadInt("ScreenWindowed") != false;

		if (CommandLine()->CheckParm("-sw") || CommandLine()->CheckParm("-startwindowed") || CommandLine()->CheckParm("-windowed") || CommandLine()->CheckParm("-window"))
			bSaveWindowed = true;
		else if (CommandLine()->CheckParm("-full") || CommandLine()->CheckParm("-fullscreen"))
			bSaveWindowed = false;

		iSaveWidth = registry->ReadInt("ScreenWidth", 1024);

		if (CommandLine()->CheckParm("-width", &pszValues))
			iSaveWidth = atoi(pszValues);

		if (CommandLine()->CheckParm("-w", &pszValues))
			iSaveWidth = atoi(pszValues);

		iSaveHeight = registry->ReadInt("ScreenHeight", 768);

		if (CommandLine()->CheckParm("-height", &pszValues))
			iSaveHeight = atoi(pszValues);

		if (CommandLine()->CheckParm("-h", &pszValues))
			iSaveHeight = atoi(pszValues);

		iSaveBPP = registry->ReadInt("ScreenBPP", 32);

		if (CommandLine()->CheckParm("-16bpp"))
			iSaveBPP = 16;
		else if (CommandLine()->CheckParm("-24bpp"))
			iSaveBPP = 24;
		else if (CommandLine()->CheckParm("-32bpp"))
			iSaveBPP = 32;

		if (width)
			*width = iSaveWidth;

		if (height)
			*height = iSaveHeight;

		if (bpp)
			*bpp = iSaveBPP;

		if (windowed)
			*windowed = bSaveWindowed;

		g_bSaveVideo = true;
	}

	return iSaveMode;*/
	return 0;
}

DWORD GetEngineVersion(void)
{
	/*if (!g_pfnbuild_number)
		return 0;

	return g_pfnbuild_number();*/
	return 0;
}

metahook_api_t gMetaHookAPI =
{
	UnHook,
	InlineHook,
	VFTHook,
	IATHook,
	GetClassFuncAddr,
	GetModuleBase,
	GetModuleSize,
	GetEngineModule,
	GetEngineBase,
	GetEngineSize,
	SearchPattern,
	WriteDWORD,
	ReadDWORD,
	WriteMemory,
	ReadMemory,
	GetVideoMode,
	GetEngineVersion,
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               