#include "hook.h"
#include "hookutils.h"
#include <stdio.h>
#include <locale.h>
#include <ICommandLine.h>
#include <IGameUI.h>
#include <VGUI/IPanel.h>
#include "DediCsv.h"
#include "ChattingManager.h"
#include <IFileSystem.h>

#define MAX_ZIP_SIZE	(1024 * 1024 * 16 )
#include "XZip.h"

#include <vector>
#include <string>
#include <unordered_map>
#include "sys.h"

HMODULE g_hEngineModule;
DWORD g_dwEngineBase;
DWORD g_dwEngineSize;

DWORD g_dwGameUIBase;
DWORD g_dwGameUISize;

DWORD g_dwMpBase;
DWORD g_dwMpSize;

DWORD g_dwFileSystemBase;
DWORD g_dwFileSystemSize;

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT "30002"

#define SOCKETMANAGER_SIG_CSNZ23 "\xE8\x00\x00\x00\x00\xEB\x00\x33\xC0\xFF\x75\x00\xA3"
#define SOCKETMANAGER_MASK_CSNZ23 "x????x?xxxx?x"

#define SERVERCONNECT_SIG_CSNZ2019 "\xE8\x00\x00\x00\x00\x85\xC0\x75\x00\x46"
#define SERVERCONNECT_MASK_CSNZ2019 "x????xxx?x"

#define PACKET_METADATA_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x89\xB5\x00\x00\x00\x00\x8B\x45\x00\x89\x85"
#define PACKET_METADATA_PARSE_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xxxx????xx?xx"

#define PACKET_QUEST_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x8B\x45\x00\x89\x45\x00\x8B\x45\x00\xC7\x45\x00\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\x89\x45\x00\x6A\x00\x8D\x45\x00\xC7\x45\x00\x00\x00\x00\x00\x50\x8D\x4D\x00\xE8\x00\x00\x00\x00\x0F\xB6\x45\x00\x89\x47\x00\xE8\x00\x00\x00\x00\x8B\x47\x00\x48"
#define PACKET_QUEST_PARSE_MASK_CSNZ "xxxx?x????xx????xxx?xxxx????xxxxx?xx????xxxx?xx?xx?xx?????xx?????xx?x?xx?xx?????xxx?x????xxx?xx?x????xx?x"

#define PACKET_UMSG_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89\xBD"
#define PACKET_UMSG_PARSE_MASK_CSNZ "xxxx?x????xx????xx????x????x????xxxx?xxxxx?xx????xxxx"

#define PACKET_ALARM_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF9\x89\xBD\x00\x00\x00\x00\x8B\x45\x00\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x8B\x45\x00\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x6A\x00\x8D\x85\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\x50\x8D\x8D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x0F\xB6\x85\x00\x00\x00\x00\x83\xF8"
#define PACKET_ALARM_PARSE_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xxxx????xx?xx????????xx????xx?xx????????xx????????xx????x?xx????xx?????xxx????x????xxx????xx"

#define PACKET_ITEM_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xF1\x8B\x45\x00\xC7\x85"
#define PACKET_ITEM_PARSE_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxx?xx????xxxx?xx"

#define PACKET_CRYPT_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x53\x56\x57\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\x45\x00\x89\x85\x00\x00\x00\x00\x8B\x45\x00\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x6A\x00\x8D\x85\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\x50\x8D\x8D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x0F\xB6\x9D"
#define PACKET_CRYPT_PARSE_MASK_CSNZ "xxxx?x????xx????xxx????x????xxxx?xxxxxx?xx????xx?xx????xx?xx????????xx????????xx????x?xx????xx?????xxx????x????xxx"

#define PACKET_HACK_PARSE_SIG_CSNZ "\x55\x8B\xEC\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x00\x53\x56\x57\xA1\x00\x00\x00\x00\x33\xC5\x50\x8D\x45\x00\x64\xA3\x00\x00\x00\x00\x8B\xD9\x89\x5D\x00\x8B\x45\x00\x89\x45\x00\x8B\x45\x00\xC7\x45\x00\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\x89\x45\x00\x6A\x00\x8D\x45\x00\xC7\x45\x00\x00\x00\x00\x00\x50\x8D\x4D\x00\xE8\x00\x00\x00\x00\x0F\xB6\x45\x00\x89\x43\x00\x83\xE8"
#define PACKET_HACK_PARSE_MASK_CSNZ "xxxx?x????xx????xxx?xxxx????xxxxx?xx????xxxx?xx?xx?xx?xx?????xx?????xx?x?xx?xx?????xxx?x????xxx?xx?xx"

#define PACKET_HACK_SEND_SIG_CSNZ "\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xEB\x00\x43\x56\x20\x20\x0D"
#define PACKET_HACK_SEND_MASK_CSNZ "x????x????x?xxxxx"

#define BOT_MANAGER_PTR_SIG_CSNZ "\xA3\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x83\xC4"
#define BOT_MANAGER_PTR_MASK_CSNZ "x????xx?????xx????xx"

#define CSOMAINPANEL_PTR_SIG_CSNZ "\x8B\x0D\x00\x00\x00\x00\x6A\x01\x8B\x01\xFF\x90\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\x6A\x01\xE8\x00\x00\x00\x00\x8B\x03"
#define CSOMAINPANEL_PTR_MASK_CSNZ "xx????xxxxxx????xx????xxx????xx"

#define CALL_PANEL_FINDCHILDBYNAME_SIG_CSNZ "\xE8\x00\x00\x00\x00\x85\xC0\x74\x00\x83\x7D"
#define CALL_PANEL_FINDCHILDBYNAME_MASK_CSNZ "x????xxx?xx"

#define NGCLIENT_INIT_SIG_CSNZ "\xE8\x00\x00\x00\x00\x84\xC0\x75\x00\xE8\x00\x00\x00\x00\x33\xC0"
#define NGCLIENT_INIT_MASK_CSNZ "x????xxx?x????xx"

#define NGCLIENT_QUIT_SIG_CSNZ "\xE8\x00\x00\x00\x00\x33\xC0\xE9\x00\x00\x00\x00\xEB"
#define NGCLIENT_QUIT_MASK_CSNZ "x????xxx????x"

#define HOLEPUNCH_SETSERVERINFO_SIG_CSNZ "\x55\x8B\xEC\xB8\x00\x00\x00\x00\x66\xA3"
#define HOLEPUNCH_SETSERVERINFO_MASK_CSNZ "xxxx????xx"

#define HOLEPUNCH_GETUSERSOCKETINFO_SIG_CSNZ "\x55\x8B\xEC\x83\xEC\x00\x57\x8B\x7D\x00\x85\xFF\x75\x00\x8B\x45"
#define HOLEPUNCH_GETUSERSOCKETINFO_MASK_CSNZ "xxxxx?xxx?xxx?xx"

#define CREATESTRINGTABLE_SIG_CSNZ "\x55\x8B\xEC\x53\x56\x8B\xF1\xC7\x46"
#define CREATESTRINGTABLE_MASK_CSNZ "xxxxxxxxx"

#define LOADJSON_SIG_CSNZ "\x55\x8B\xEC\x8B\x0D\x00\x00\x00\x00\x53\x56\x8B\x75\x00\x8B\x01\x57\x8B\x50\x00\x8B\x45\x00\x83\x78\x00\x00\x76\x00\x8B\x00\x6A\x00\x68\x00\x00\x00\x00\x50\xFF\xD2\x8B\x0D\x00\x00\x00\x00\x8B\xD8\x53\x8B\x11\xFF\x52\x00\x8B\xF8\x85\xFF\x74"
#define LOADJSON_MASK_CSNZ "xxxxx????xxxx?xxxxx?xx?xx??x?xxx?x????xxxxx????xxxxxxx?xxxxx"

#define LOGTOERRORLOG_SIG_CSNZ "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\x00\x56\x8B\x75\x00\x8D\x45\x00\x57"
#define LOGTOERRORLOG_MASK_CSNZ "xxxxx????x????xxxx?xxx?xx?x"

#define READPACKET_SIG_CSNZ "\xE8\x00\x00\x00\x00\x8B\xF0\x83\xFE\x00\x77"
#define READPACKET_MASK_CSNZ "x????xxxx?x"

#define GETSSLPROTOCOLNAME_SIG_CSNZ "\xE8\x00\x00\x00\x00\xB9\x00\x00\x00\x00\x8A\x10"
#define GETSSLPROTOCOLNAME_MASK_CSNZ "x????x????xx"

#define SOCKETCONSTRUCTOR_SIG_CSNZ "\xE8\x00\x00\x00\x00\xEB\x00\x33\xC0\x53\xC7\x45"
#define SOCKETCONSTRUCTOR_MASK_CSNZ "x????x?xxxxx"

#define EVP_CIPHER_CTX_NEW_SIG_CSNZ "\xE8\x00\x00\x00\x00\x8B\xF8\x89\xBE"
#define EVP_CIPHER_CTX_NEW_MASK_CSNZ "x????xxxx"

char g_pServerIP[16];
char g_pServerPort[6];
char g_pLogin[64];
char g_pPassword[64];

bool g_bUseOriginalServer = false;
bool g_bDumpMetadata = false;
bool g_bIgnoreMetadata = false;
bool g_bDumpQuest = false;
bool g_bDumpUMsg = false;
bool g_bDumpAlarm = false;
bool g_bDumpItem = false;
bool g_bDumpCrypt = false;
bool g_bDumpAll = false;
bool g_bDisableAuthUI = false;
bool g_bUseSSL = false;
bool g_bWriteMetadata = false;
bool g_bLoadDediCsvFromFile = false;
bool g_bRegister = false;
bool g_bNoNGHook = false;

cl_enginefunc_t* g_pEngine;

class CCSBotManager
{
public:
	virtual void Unknown() = NULL;
	virtual void Bot_Add(int side) = NULL;
};

CCSBotManager* g_pBotManager = NULL;

vgui::IPanel* g_pPanel = nullptr;
IGameUI* g_pGameUI = nullptr;
ChattingManager* g_pChattingManager;

WNDPROC oWndProc;
HWND hWnd;

int(__thiscall* g_pfnGameUI_RunFrame)(void* _this);

typedef void* (__thiscall* tPanel_FindChildByName)(void* _this, const char* name, bool recurseDown);
tPanel_FindChildByName g_pfnPanel_FindChildByName;

typedef int(__thiscall* tLoginDlg_OnCommand)(void* _this, const char* command);
tLoginDlg_OnCommand g_pfnLoginDlg_OnCommand;

typedef void(__thiscall* tParseCSV)(int* _this, unsigned char* buffer, int size);
tParseCSV g_pfnParseCSV;

typedef void*(*tEVP_CIPHER_CTX_new)();
tEVP_CIPHER_CTX_new g_pfnEVP_CIPHER_CTX_new;

#pragma region Nexon NGClient/NXGSM
char NGClient_Return1()
{
	return 1;
}

void NGClient_Void()
{
}

// logger shit
bool NXGSM_Dummy()
{
	return false;
}

void NXGSM_WriteStageLogA(int a1, char* a2)
{
}

void NXGSM_WriteErrorLogA(int a1, char* a2)
{
}
#pragma endregion

void Pbuf_AddText(const char* text)
{
	g_pEngine->pfnClientCmd((char*)text);
}

CreateHookClass(void*, SocketManagerConstructor, bool useSSL)
{
	return g_pfnSocketManagerConstructor(ptr, g_bUseSSL);
}

CreateHookClass(int, ServerConnect, unsigned long ip, unsigned short port, bool validate)
{
	return g_pfnServerConnect(ptr, inet_addr(g_pServerIP), htons(atoi(g_pServerPort)), validate);
}

CreateHook(__cdecl, void, HolePunch_SetServerInfo, unsigned long ip, unsigned short port)
{
	g_pfnHolePunch_SetServerInfo(inet_addr(g_pServerIP), htons(atoi(g_pServerPort)));
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == 0x113 && wParam == 250)
	{
		// handle dropclient msg if the client detected abnormal things
		printf("handle_dropclient\n");
		return 0;
	}
	return CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam);
}

enum dediCsvType {
	TDM_Spawn_Replacement,
	AllStar_Skill,
	AllStar_Status,
	LastStand,
	ProtectionSupplyWeapon,
	RandomRule_Classic,
	RandomRule,
	ZSRogueLiteAbility,
	ZSTransform_Skill,
	ZSTransform_Status,
	FireBombOption,
	ZombieSkillProperty_Crazy,
	ZombieSkillProperty_JumpBuff,
	ZombieSkillProperty_ArmorUp,
	ZombieSkillProperty_Heal,
	ZombieSkillProperty_ShieldBuf,
	ZombieSkillProperty_Cloacking,
	ZombieSkillProperty_Trap,
	ZombieSkillProperty_Smoke,
	ZombieSkillProperty_VoodooHeal,
	ZombieSkillProperty_Shock,
	ZombieSkillProperty_Rush,
	ZombieSkillProperty_Pile,
	ZombieSkillProperty_Bat,
	ZombieSkillProperty_Stiffen,
	ZombieSkillProperty_SelfDestruct,
	ZombieSkillProperty_Penetration,
	ZombieSkillProperty_Revival,
	ZombieSkillProperty_Telleport,
	ZombieSkillProperty_Boost,
	ZombieSkillProperty_BombCreate,
	ZombieSkillProperty_Flying,
	ZombieSkillProperty_Fireball,
	ZombieSkillProperty_DogShoot,
	ZombieSkillProperty_ViolentRush,
	ZombieSkillProperty_WebShooter,
	ZombieSkillProperty_WebBomb,
	ZombieSkillProperty_Protect,
	ZombieSkillProperty_ChargeSlash,
	ZombieSkillProperty_Claw,
	HumanAbilityData,
	HumanAbilityProbData,
	SpecialZombieProb,
	VirusFactorReq,
	ZombiVirusBonus
};

std::unordered_map<std::string, dediCsvType> dediCsv = {
	{ "maps/TDM_Spawn_Replacement_Dedi.csv", TDM_Spawn_Replacement },
	{ "resource/allstar/AllStar_Skill-Dedi.csv", AllStar_Skill },
	{ "resource/allstar/AllStar_Status-Dedi.csv", AllStar_Status },
	{ "resource/ModeEvent/LastStand_Dedi.csv", LastStand },
	{ "resource/ModeEvent/ProtectionSupplyWeapon_Dedi.csv", ProtectionSupplyWeapon },
	{ "resource/ModeEvent/RandomRule_Classic_Dedi.csv", RandomRule_Classic },
	{ "resource/ModeEvent/RandomRule_Dedi.csv", RandomRule },
	{ "resource/ModeEvent/ZSRogueLiteAbility_Dedi.csv", ZSRogueLiteAbility },
	{ "resource/ModeEvent/ZSTransform_Skill-Dedi.csv", ZSTransform_Skill },
	{ "resource/ModeEvent/ZSTransform_Status-Dedi.csv", ZSTransform_Status },
	{ "resource/zombi/FireBombOption_Dedi.csv", FireBombOption },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Crazy.csv", ZombieSkillProperty_Crazy },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_JumpBuff.csv", ZombieSkillProperty_JumpBuff },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_ArmorUp.csv", ZombieSkillProperty_ArmorUp },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Heal.csv", ZombieSkillProperty_Heal },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_ShieldBuf.csv", ZombieSkillProperty_ShieldBuf },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Cloacking.csv", ZombieSkillProperty_Cloacking },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Trap.csv", ZombieSkillProperty_Trap },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Smoke.csv", ZombieSkillProperty_Smoke },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_VoodooHeal.csv", ZombieSkillProperty_VoodooHeal },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Shock.csv", ZombieSkillProperty_Shock },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Rush.csv", ZombieSkillProperty_Rush },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Pile.csv", ZombieSkillProperty_Pile },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Bat.csv", ZombieSkillProperty_Bat },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Stiffen.csv", ZombieSkillProperty_Stiffen },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_SelfDestruct.csv", ZombieSkillProperty_SelfDestruct },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Penetration.csv", ZombieSkillProperty_Penetration },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Revival.csv", ZombieSkillProperty_Revival },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Telleport.csv", ZombieSkillProperty_Telleport },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Boost.csv", ZombieSkillProperty_Boost },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_BombCreate.csv", ZombieSkillProperty_BombCreate },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Flying.csv", ZombieSkillProperty_Flying },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Fireball.csv", ZombieSkillProperty_Fireball },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_DogShoot.csv", ZombieSkillProperty_DogShoot },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_ViolentRush.csv", ZombieSkillProperty_ViolentRush },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_WebShooter.csv", ZombieSkillProperty_WebShooter },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_WebBomb.csv", ZombieSkillProperty_WebBomb },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Protect.csv", ZombieSkillProperty_Protect },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_ChargeSlash.csv", ZombieSkillProperty_ChargeSlash },
	{ "resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Claw.csv", ZombieSkillProperty_Claw },
	{ "resource/zombi5/HumanAbilityData_Dedi.csv", HumanAbilityData },
	{ "resource/zombi5/HumanAbilityProbData_Dedi.csv", HumanAbilityProbData },
	{ "resource/zombi5/SpecialZombieProb_Dedi.csv", SpecialZombieProb },
	{ "resource/zombi5/VirusFactorReq_Dedi.csv", VirusFactorReq },
	{ "resource/zombi5/ZombiVirusBonus_Dedi.csv", ZombiVirusBonus }
};

bool LoadCsv(int* _this, const char* filename, unsigned char* defaultBuf, int defaultBufSize)
{
	unsigned char* buffer = NULL;
	long size = 0;

	if (g_bLoadDediCsvFromFile)
	{
		char path[MAX_PATH];
		snprintf(path, sizeof(path), "%s/Data/%s", Sys_GetLongPathNameWithoutBin(), filename);

		FILE* file = fopen(path, "rb");
		if (!file)
		{
			printf("LoadCsv: %s failed to load from file (file == NULL), loading from filesystem\n", filename);
			goto LoadFileSystem;
		}

		fseek(file, 0, SEEK_END);
		size = ftell(file);
		rewind(file);

		if (size)
		{
			buffer = (unsigned char*)malloc(size);
			if (buffer)
				fread(buffer, 1, size, file);
			else
				printf("LoadCsv: %s failed to load from file (malloc failed), loading from filesystem\n", filename);
		}
		else
			printf("LoadCsv: %s failed to load from file (size <= 0), loading from filesystem\n", filename);

		fclose(file);

		if (buffer)
			goto SetBuffer;
	}

LoadFileSystem:
	FileHandle_t fh = g_pFileSystem->Open(filename, "rb", 0);
	if (!fh)
	{
		printf("LoadCsv: %s failed to load from filesystem (fh == NULL), loading hardcoded values\n", filename);
		goto LoadDefaultBuf;
	}

	size = g_pFileSystem->Size(fh);
	if (size)
	{
		buffer = (unsigned char*)malloc(size);
		if (buffer)
			g_pFileSystem->Read(buffer, size, fh);
		else
			printf("LoadCsv: %s failed to load from filesystem (malloc failed), loading hardcoded values\n", filename);
	}
	else
		printf("LoadCsv: %s failed to load from filesystem (size <= 0), loading hardcoded values\n", filename);

	g_pFileSystem->Close(fh);

	if (buffer)
		goto SetBuffer;

LoadDefaultBuf:
	buffer = defaultBuf;
	size = defaultBufSize;

SetBuffer:
	g_pfnParseCSV(_this, buffer, size);

	bool result = 0;
	if (_this[2])
		result = _this[3] != 0;

	return result;
}

CreateHookClassType(bool, CreateStringTable, int, const char* filename)
{
	std::string filenameStr = filename;
	if (filenameStr.find("maps/BoostingPoints_Dedi_") != std::string::npos)
		return LoadCsv(ptr, filename, NULL, NULL);

	if (dediCsv.find(filename) != dediCsv.end())
	{
		switch (dediCsv[filename])
		{
		case TDM_Spawn_Replacement: return LoadCsv(ptr, filename, g_TDM_Spawn_Replacement, sizeof(g_TDM_Spawn_Replacement));
		case AllStar_Skill: return LoadCsv(ptr, filename, g_AllStar_Skill, sizeof(g_AllStar_Skill));
		case AllStar_Status: return LoadCsv(ptr, filename, g_AllStar_Status, sizeof(g_AllStar_Status));
		case LastStand: return LoadCsv(ptr, filename, g_LastStand, sizeof(g_LastStand));
		case ProtectionSupplyWeapon: return LoadCsv(ptr, filename, g_ProtectionSupplyWeapon, sizeof(g_ProtectionSupplyWeapon));
		case RandomRule_Classic: return LoadCsv(ptr, filename, g_RandomRule_Classic, sizeof(g_RandomRule_Classic));
		case RandomRule: return LoadCsv(ptr, filename, g_RandomRule, sizeof(g_RandomRule));
		case ZSRogueLiteAbility: return LoadCsv(ptr, filename, g_ZSRogueLiteAbility, sizeof(g_ZSRogueLiteAbility));
		case ZSTransform_Skill: return LoadCsv(ptr, filename, g_ZSTransform_Skill, sizeof(g_ZSTransform_Skill));
		case ZSTransform_Status: return LoadCsv(ptr, filename, g_ZSTransform_Status, sizeof(g_ZSTransform_Status));
		case FireBombOption: return LoadCsv(ptr, filename, g_FireBombOption, sizeof(g_FireBombOption));
		case HumanAbilityData: return LoadCsv(ptr, filename, g_HumanAbilityData, sizeof(g_HumanAbilityData));
		case HumanAbilityProbData: return LoadCsv(ptr, filename, g_HumanAbilityProbData, sizeof(g_HumanAbilityProbData));
		case SpecialZombieProb: return LoadCsv(ptr, filename, g_SpecialZombieProb, sizeof(g_SpecialZombieProb));
		case VirusFactorReq: return LoadCsv(ptr, filename, g_VirusFactorReq, sizeof(g_VirusFactorReq));
		case ZombiVirusBonus: return LoadCsv(ptr, filename, g_ZombiVirusBonus, sizeof(g_ZombiVirusBonus));
		}
	}

	return g_pfnCreateStringTable(ptr, filename);
}

bool LoadJson(std::string* filename, std::string* oriBuf, unsigned char* defaultBuf, int defaultBufSize)
{
	unsigned char* buffer = NULL;
	long size = 0;

	if (g_bLoadDediCsvFromFile)
	{
		char path[MAX_PATH];
		snprintf(path, sizeof(path), "%s/Data/%s", Sys_GetLongPathNameWithoutBin(), filename->c_str());

		FILE* file = fopen(path, "rb");
		if (!file)
		{
			printf("LoadJson: %s failed to load from file (file == NULL), loading from filesystem\n", filename->c_str());
			goto LoadFileSystem;
		}

		fseek(file, 0, SEEK_END);
		size = ftell(file);
		rewind(file);

		if (size)
		{
			buffer = (unsigned char*)malloc(size);
			if (buffer)
				fread(buffer, 1, size, file);
			else
				printf("LoadJson: %s failed to load from file (malloc failed), loading from filesystem\n", filename->c_str());
		}
		else
			printf("LoadJson: %s failed to load from file (size <= 0), loading from filesystem\n", filename->c_str());

		fclose(file);

		if (buffer)
			goto SetBuffer;
	}

LoadFileSystem:
	FileHandle_t fh = g_pFileSystem->Open(filename->c_str(), "r", 0);
	if (!fh)
	{
		printf("LoadJson: %s failed to load from filesystem (fh == NULL), loading hardcoded values\n", filename->c_str());
		goto LoadDefaultBuf;
	}

	size = g_pFileSystem->Size(fh);
	if (size)
	{
		buffer = (unsigned char*)malloc(size);
		if (buffer)
			g_pFileSystem->Read(buffer, size, fh);
		else
			printf("LoadJson: %s failed to load from filesystem (malloc failed), loading hardcoded values\n", filename->c_str());
	}
	else
		printf("LoadJson: %s failed to load from filesystem (size <= 0), loading hardcoded values\n", filename->c_str());

	g_pFileSystem->Close(fh);

	if (buffer)
		goto SetBuffer;

LoadDefaultBuf:
	buffer = defaultBuf;
	size = defaultBufSize;

SetBuffer:
	*oriBuf = std::string((char*)buffer, (char*)buffer + size);

	return 1;
}

CreateHook(__stdcall, int, LoadJson, std::string* filename, std::string* buffer)
{
	if (dediCsv.find(*filename) != dediCsv.end())
	{
		switch (dediCsv[*filename])
		{
		case ZombieSkillProperty_Crazy: return LoadJson(filename, buffer, g_ZombieSkillProperty_Crazy, sizeof(g_ZombieSkillProperty_Crazy));
		case ZombieSkillProperty_JumpBuff: return LoadJson(filename, buffer, g_ZombieSkillProperty_JumpBuff, sizeof(g_ZombieSkillProperty_JumpBuff));
		case ZombieSkillProperty_ArmorUp: return LoadJson(filename, buffer, g_ZombieSkillProperty_ArmorUp, sizeof(g_ZombieSkillProperty_ArmorUp));
		case ZombieSkillProperty_Heal: return LoadJson(filename, buffer, g_ZombieSkillProperty_Heal, sizeof(g_ZombieSkillProperty_Heal));
		case ZombieSkillProperty_ShieldBuf: return LoadJson(filename, buffer, g_ZombieSkillProperty_ShieldBuf, sizeof(g_ZombieSkillProperty_ShieldBuf));
		case ZombieSkillProperty_Cloacking: return LoadJson(filename, buffer, g_ZombieSkillProperty_Cloacking, sizeof(g_ZombieSkillProperty_Cloacking));
		case ZombieSkillProperty_Trap: return LoadJson(filename, buffer, g_ZombieSkillProperty_Trap, sizeof(g_ZombieSkillProperty_Trap));
		case ZombieSkillProperty_Smoke: return LoadJson(filename, buffer, g_ZombieSkillProperty_Smoke, sizeof(g_ZombieSkillProperty_Smoke));
		case ZombieSkillProperty_VoodooHeal: return LoadJson(filename, buffer, g_ZombieSkillProperty_VoodooHeal, sizeof(g_ZombieSkillProperty_VoodooHeal));
		case ZombieSkillProperty_Shock: return LoadJson(filename, buffer, g_ZombieSkillProperty_Shock, sizeof(g_ZombieSkillProperty_Shock));
		case ZombieSkillProperty_Rush: return LoadJson(filename, buffer, g_ZombieSkillProperty_Rush, sizeof(g_ZombieSkillProperty_Rush));
		case ZombieSkillProperty_Pile: return LoadJson(filename, buffer, g_ZombieSkillProperty_Pile, sizeof(g_ZombieSkillProperty_Pile));
		case ZombieSkillProperty_Bat: return LoadJson(filename, buffer, g_ZombieSkillProperty_Bat, sizeof(g_ZombieSkillProperty_Bat));
		case ZombieSkillProperty_Stiffen: return LoadJson(filename, buffer, g_ZombieSkillProperty_Stiffen, sizeof(g_ZombieSkillProperty_Stiffen));
		case ZombieSkillProperty_SelfDestruct: return LoadJson(filename, buffer, g_ZombieSkillProperty_SelfDestruct, sizeof(g_ZombieSkillProperty_SelfDestruct));
		case ZombieSkillProperty_Penetration: return LoadJson(filename, buffer, g_ZombieSkillProperty_Penetration, sizeof(g_ZombieSkillProperty_Penetration));
		case ZombieSkillProperty_Revival: return LoadJson(filename, buffer, g_ZombieSkillProperty_Revival, sizeof(g_ZombieSkillProperty_Revival));
		case ZombieSkillProperty_Telleport: return LoadJson(filename, buffer, g_ZombieSkillProperty_Telleport, sizeof(g_ZombieSkillProperty_Telleport));
		case ZombieSkillProperty_Boost: return LoadJson(filename, buffer, g_ZombieSkillProperty_Boost, sizeof(g_ZombieSkillProperty_Boost));
		case ZombieSkillProperty_BombCreate: return LoadJson(filename, buffer, g_ZombieSkillProperty_BombCreate, sizeof(g_ZombieSkillProperty_BombCreate));
		case ZombieSkillProperty_Flying: return LoadJson(filename, buffer, g_ZombieSkillProperty_Flying, sizeof(g_ZombieSkillProperty_Flying));
		case ZombieSkillProperty_Fireball: return LoadJson(filename, buffer, g_ZombieSkillProperty_Fireball, sizeof(g_ZombieSkillProperty_Fireball));
		case ZombieSkillProperty_DogShoot: return LoadJson(filename, buffer, g_ZombieSkillProperty_DogShoot, sizeof(g_ZombieSkillProperty_DogShoot));
		case ZombieSkillProperty_ViolentRush: return LoadJson(filename, buffer, g_ZombieSkillProperty_ViolentRush, sizeof(g_ZombieSkillProperty_ViolentRush));
		case ZombieSkillProperty_WebShooter: return LoadJson(filename, buffer, g_ZombieSkillProperty_WebShooter, sizeof(g_ZombieSkillProperty_WebShooter));
		case ZombieSkillProperty_WebBomb: return LoadJson(filename, buffer, g_ZombieSkillProperty_WebBomb, sizeof(g_ZombieSkillProperty_WebBomb));
		case ZombieSkillProperty_Protect: return LoadJson(filename, buffer, g_ZombieSkillProperty_Protect, sizeof(g_ZombieSkillProperty_Protect));
		case ZombieSkillProperty_ChargeSlash: return LoadJson(filename, buffer, g_ZombieSkillProperty_ChargeSlash, sizeof(g_ZombieSkillProperty_ChargeSlash));
		case ZombieSkillProperty_Claw: return LoadJson(filename, buffer, g_ZombieSkillProperty_Claw, sizeof(g_ZombieSkillProperty_Claw));
		}
	}

	return g_pfnLoadJson(filename, buffer);
}

enum metaDataType
{
	zipMetadata,
	binToJsonMetadata,
	binMetadata
};

metaDataType GetMetadataType(int metaDataID)
{
	switch (metaDataID)
	{
	case 0:
	case 1:
	case 2:
	case 9:
	case 17:
	case 18:
	case 24:
	case 25:
	case 26:
	case 27:
	case 28:
	case 29:
	case 32:
	case 33:
	case 34:
	case 35:
	case 36:
	case 37:
	case 38:
	case 39:
	case 40:
	case 41:
	case 42:
	case 44:
	case 45:
	case 46:
	case 48:
	case 50:
	case 51:
	case 52:
	case 53:
		return zipMetadata;
	case 6:
	case 15:
	case 16:
		return binToJsonMetadata;
	default:
		return binMetadata;
	}
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
	case 6:
		return "WeaponPaints";
	case 9:
		return "MatchOption.csv";
	case 15:
		return "ZombieWarWeaponList";
	case 16:
		return "RandomWeaponList";
	case 17:
		return "weaponparts.csv";
	case 18:
		return "MileageShop.csv";
	case 24:
		return "GameModeList.csv";
	case 25:
		return "badwordadd.csv";
	case 26:
		return "badworddel.csv";
	case 27:
		return "progress_unlock.csv";
	case 28:
		return "ReinforceMaxLv.csv";
	case 29:
		return "ReinforceMaxExp.csv";
	case 30:
		return "ReinforceItemsExp";
	case 32:
		return "Item.csv";
	case 33:
		return "voxel_list.csv";
	case 34:
		return "voxel_item.csv";
	case 35:
		return "CodisData.csv";
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
	case 41:
		return "EpicPieceShop.csv";
	case 42:
		return "WeaponProp.json";
	case 44:
		return "SeasonBadgeShop.csv";
	case 45:
		return "ppsystem.json";
	case 46:
		return "classmastery.json";
	case 48:
		return "ZBCompetitive.json"; // required or game will crash
	case 50:
		return "ModeEvent.csv";
	case 51:
		return "EventShop.csv";
	case 52:
		return "FamilyTotalWarMap.csv";
	case 53:
		return "FamilyTotalWar.json";
	}
	return NULL;
}

#pragma region Packet
void* g_pPacketMetadataParse;

CreateHookClass(int, Packet_Metadata_Parse, void* packetBuffer, int packetSize)
{
	g_pPacketMetadataParse = ptr;

	if (g_bIgnoreMetadata)
	{
		return false;
	}

	unsigned char metaDataID = *(unsigned char*)packetBuffer;
	printf("Received metadata ID %d\n", metaDataID);

	metaDataType metaDataType = GetMetadataType(metaDataID);
	const char* metaDataName = GetMetadataName(metaDataID);

	if (g_bDumpMetadata)
	{
		char name[MAX_PATH];
		FILE* file = NULL;
		unsigned short metaDataSize = 0;

		CreateDirectory("MetadataDump", NULL);

		switch (metaDataType)
		{
		case zipMetadata:
		{
			metaDataSize = *((unsigned short*)((char*)packetBuffer + 1));

			sprintf_s(name, "MetadataDump/Metadata_%s.zip", metaDataName);
			break;
		}
		case binToJsonMetadata:
		{
			sprintf_s(name, "MetadataDump/%s.json", metaDataName);
			file = fopen(name, "wb");
			if (!file)
			{
				printf("Can't open '%s' file to write metadata dump\n", name);
			}
			else
			{
				switch (metaDataID)
				{
				case 6:
				{
					fwrite("{\n\t\"Version\": 1,\n", 17, 1, file);

					int offset = 1;
					int size = *((unsigned short*)((char*)packetBuffer + offset)); offset += 2;

					for (int i = 0; i < size; i++)
					{
						int weaponID = *((unsigned short*)((char*)packetBuffer + offset)); offset += 2;
						int size2 = *((unsigned short*)((char*)packetBuffer + offset)); offset += 2;

						char weaponIDStr[32];
						int weaponIDSize = sprintf_s(weaponIDStr, "\t\"%d\": {\n\t\t\"Paints\": [\n", weaponID);
						fwrite(weaponIDStr, weaponIDSize, 1, file);

						for (int j = 0; j < size2; j++)
						{
							int paintID = *((unsigned short*)((char*)packetBuffer + offset)); offset += 2;

							char paintIDStr[16];
							int paintIDSize = sprintf_s(paintIDStr, "\t\t\t%d", paintID);
							fwrite(paintIDStr, paintIDSize, 1, file);

							if (size2 - 1 != j)
								fwrite(",", 1, 1, file);

							fwrite("\n", 1, 1, file);
						}

						fwrite("\t\t]\n\t}", 6, 1, file);

						if (size - 1 != i)
							fwrite(",", 1, 1, file);

						fwrite("\n", 1, 1, file);
					}

					fwrite("}", 1, 1, file);
					break;
				}
				case 15:
				{
					fwrite("{\n\t\"Version\": 1,\n\t\"Weapons\": [\n", 31, 1, file);

					int offset = 1;
					int size = *((unsigned short*)((char*)packetBuffer + offset)); offset += 2;

					for (int i = 0; i < size; i++)
					{
						int itemID = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;

						char itemIDStr[16];
						int itemIDSize = sprintf_s(itemIDStr, "\t\t%d", itemID);
						fwrite(itemIDStr, itemIDSize, 1, file);

						if (size - 1 != i)
							fwrite(",", 1, 1, file);

						fwrite("\n", 1, 1, file);
					}

					fwrite("\t]\n}", 4, 1, file);
					break;
				}
				case 16:
				{
					fwrite("{\n\t\"Version\": 1,\n", 17, 1, file);

					int offset = 1;
					int size = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;

					for (int i = 0; i < size; i++)
					{
						int itemID = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;
						int size2 = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;

						char itemIDStr[16];
						int itemIDSize = sprintf_s(itemIDStr, "\t\"%d\": {\n", itemID);
						fwrite(itemIDStr, itemIDSize, 1, file);

						for (int j = 0; j < size2; j++)
						{
							int modeFlag = *((unsigned char*)((char*)packetBuffer + offset)); offset++;
							int dropRate = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;
							int enhanceProbability = *((unsigned long*)((char*)packetBuffer + offset)); offset += 4;

							char modeFlagStr[16];
							int modeFlagSize = sprintf_s(modeFlagStr, "\t\t\"%d\": {\n", modeFlag);
							fwrite(modeFlagStr, modeFlagSize, 1, file);

							char dropRateStr[32];
							int dropRateSize = sprintf_s(dropRateStr, "\t\t\t\"DropRate\": %d,\n", dropRate);
							fwrite(dropRateStr, dropRateSize, 1, file);

							char enhanceProbabilityStr[32];
							int enhanceProbabilitySize = sprintf_s(enhanceProbabilityStr, "\t\t\t\"EnhanceProbability\": %d\n", enhanceProbability);
							fwrite(enhanceProbabilityStr, enhanceProbabilitySize, 1, file);

							fwrite("\t\t}", 3, 1, file);

							if (size2 - 1 != j)
								fwrite(",", 1, 1, file);

							fwrite("\n", 1, 1, file);
						}

						fwrite("\t}", 2, 1, file);

						if (size - 1 != i)
							fwrite(",", 1, 1, file);

						fwrite("\n", 1, 1, file);
					}

					fwrite("}", 1, 1, file);
					break;
				}
				}
				fclose(file);
			}
			break;
		}
		case binMetadata:
		{
			if (metaDataName)
				sprintf_s(name, "MetadataDump/Metadata_%s.bin", metaDataName);
			else
				sprintf_s(name, "MetadataDump/Metadata_Unk%d.bin", metaDataID);
			break;
		}
		}

		if (metaDataType != binToJsonMetadata)
		{
			file = fopen(name, "wb");
			if (!file)
			{
				printf("Can't open '%s' file to write metadata dump\n", name);
			}
			else
			{
				if (metaDataType == zipMetadata)
				{
					fwrite(((unsigned short*)((char*)packetBuffer + 3)), *((unsigned short*)((char*)packetBuffer + 1)), 1, file);
				}
				else
				{
					fwrite(packetBuffer, packetSize, 1, file);
				}
				fclose(file);
			}
		}
	}

	if (g_bWriteMetadata && metaDataType == zipMetadata)
	{
		HZIP hMetaData = CreateZip(0, MAX_ZIP_SIZE, ZIP_MEMORY);

		if (!hMetaData)
		{
			printf("CreateZip returned NULL.\n");
			return g_pfnPacket_Metadata_Parse(ptr, packetBuffer, packetSize);
		}

		char path[MAX_PATH];
		sprintf(path, "Metadata/%s", metaDataName);
		printf("Writing metadata from %s\n", path);

		if (ZipAdd(hMetaData, metaDataName, path, 0, ZIP_FILENAME))
		{
			printf("ZipAdd returned error.\n");
			return g_pfnPacket_Metadata_Parse(ptr, packetBuffer, packetSize);
		}

		void* buffer;
		unsigned long length = 0;
		ZipGetMemory(hMetaData, &buffer, &length);

		if (length == 0)
		{
			printf("ZipGetMemory returned zero length.\n");
			return g_pfnPacket_Metadata_Parse(ptr, packetBuffer, packetSize);
		}

		std::vector<unsigned char> destBuffer;
		std::vector<unsigned char> metaDataBuffer((char*)buffer, (char*)buffer + length);

		destBuffer.push_back(metaDataID);
		destBuffer.push_back((unsigned char)(length & 0xFF));
		destBuffer.push_back((unsigned char)(length >> 8));
		destBuffer.insert(destBuffer.end(), metaDataBuffer.begin(), metaDataBuffer.end());

		CloseZip(hMetaData);

		return g_pfnPacket_Metadata_Parse(ptr, static_cast<void*>(destBuffer.data()), destBuffer.size());
	}

	return g_pfnPacket_Metadata_Parse(ptr, packetBuffer, packetSize);
}

void Metadata_RequestAll()
{
	std::vector<unsigned char> destBuffer;

	for (int i = 0; i < 56; i++)
	{
		destBuffer.push_back(0xFF);
		destBuffer.push_back(i);

		for (int j = 0; j < 16; j++)
			destBuffer.push_back(0x00);

		g_pfnPacket_Metadata_Parse(g_pPacketMetadataParse, static_cast<void*>(destBuffer.data()), destBuffer.size());
		destBuffer.clear();
	}
}

int counter = 0;
void DumpPacket(const char* packetName, void* packetBuffer, int packetSize)
{
	//char subType = *(char*)packetBuffer;

	CreateDirectory(packetName, NULL);

	char name[MAX_PATH];
	sprintf_s(name, "%s/%s_%d.bin", packetName, packetName, counter++);

	FILE* file = fopen(name, "wb");
	if (file)
	{
		fwrite(packetBuffer, packetSize, 1, file);
		fclose(file);
	}
	else
	{
		printf("Can't open '%s' file to write %s dump\n", name, packetName);
	}
}

CreateHookClass(int, Packet_Quest_Parse, void* packetBuffer, int packetSize)
{
	DumpPacket("QuestDump", packetBuffer, packetSize);
	return g_pfnPacket_Quest_Parse(ptr, packetBuffer, packetSize);
}

CreateHookClass(int, Packet_UMsg_Parse, void* packetBuffer, int packetSize)
{
	DumpPacket("UMsgDump", packetBuffer, packetSize);
	return g_pfnPacket_UMsg_Parse(ptr, packetBuffer, packetSize);
}

CreateHookClass(int, Packet_Alarm_Parse, void* packetBuffer, int packetSize)
{
	DumpPacket("AlarmDump", packetBuffer, packetSize);
	return g_pfnPacket_Alarm_Parse(ptr, packetBuffer, packetSize);
}

CreateHookClass(int, Packet_Item_Parse, void* packetBuffer, int packetSize)
{
	DumpPacket("ItemDump", packetBuffer, packetSize);
	return g_pfnPacket_Item_Parse(ptr, packetBuffer, packetSize);
}

CreateHookClass(int, Packet_Crypt_Parse, void* packetBuffer, int packetSize)
{
	DumpPacket("CryptDump", packetBuffer, packetSize);
	return g_pfnPacket_Crypt_Parse(ptr, packetBuffer, packetSize);
}

int __fastcall Hook_Packet_Hack_Parse(void* _this, int a2, void* packetBuffer, int packetSize)
{
	return 1;
}
#pragma endregion

void __fastcall LoginDlg_OnCommand(void* _this, int r, const char* command)
{
	if (!strcmp(command, "Login"))
	{
		DWORD** v3 = (DWORD**)_this;
		char login[256];
		char password[256];

		//void* pLoginTextEntry = g_pfnPanel_FindChildByName(_this, "1");
		//void* pPasswordTextEntry = g_pfnPanel_FindChildByName(_this, "1");
		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[109] + 628))(v3[109], login, 256); // textentry->GetText() // before 23.12.23 *v3[109] + 620
		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[110] + 628))(v3[110], password, 256);

		wchar_t buf[256];
		swprintf(buf, L"/login %S %S", login, password);
		if (g_pChattingManager)
			g_pChattingManager->PrintToChat(1, buf);
		return;
	}
	else if (!strcmp(command, "Register"))
	{
		DWORD** v3 = (DWORD**)_this;
		char login[256];
		char password[256];

		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[109] + 628))(v3[109], login, 256); // textentry->GetText()
		(*(void(__thiscall**)(DWORD*, char*, signed int))(*v3[110] + 628))(v3[110], password, 256);

		wchar_t buf[256];
		swprintf(buf, L"/register %S %S", login, password);
		if (g_pChattingManager)
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
			Sleep(500);

			wchar_t buf[256];
			swprintf(buf, g_bRegister ? L"/register %S %S" : L"/login %S %S", g_pLogin, g_pPassword);
			if (g_pChattingManager)
				g_pChattingManager->PrintToChat(1, buf);
		}

		if (!g_bDisableAuthUI)
		{
			__try
			{
				void* pCSOMainPanel = **((void***)(FindPattern(CSOMAINPANEL_PTR_SIG_CSNZ, CSOMAINPANEL_PTR_MASK_CSNZ, g_dwGameUIBase, g_dwGameUIBase + g_dwGameUISize, 2)));
				if (!pCSOMainPanel)
				{
					MessageBox(NULL, "pCSOMainPanel == NULL!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
					bShowLoginDlg = true;
					return g_pfnGameUI_RunFrame(_this);
				}

				DWORD dwPanel_FindChildByNameRelAddr = FindPattern(CALL_PANEL_FINDCHILDBYNAME_SIG_CSNZ, CALL_PANEL_FINDCHILDBYNAME_MASK_CSNZ, g_dwGameUIBase, g_dwGameUIBase + g_dwGameUISize, 1);
				if (!dwPanel_FindChildByNameRelAddr)
				{
					MessageBox(NULL, "dwPanel_FindChildByNameRelAddr == NULL!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
					bShowLoginDlg = true;
					return g_pfnGameUI_RunFrame(_this);
				}
				
				g_pfnPanel_FindChildByName = (tPanel_FindChildByName)(dwPanel_FindChildByNameRelAddr + 4 + *(DWORD*)dwPanel_FindChildByNameRelAddr);
				if (!g_pfnPanel_FindChildByName)
				{
					MessageBox(NULL, "g_pfnPanel_FindChildByName == NULL!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
					bShowLoginDlg = true;
					return g_pfnGameUI_RunFrame(_this);
				}

				void* pLoginDlg = *(void**)((DWORD)pCSOMainPanel + 364);
				if (!pLoginDlg)
				{
					MessageBox(NULL, "pLoginDlg == NULL!!!\nUse -disableauthui parameter to disable VGUI login dialog", "Error", MB_OK);
					bShowLoginDlg = true;
					return g_pfnGameUI_RunFrame(_this);
				}

				VFTHook(pLoginDlg, 0, 99, LoginDlg_OnCommand, (void*&)g_pfnLoginDlg_OnCommand); // before 10.07.2024 iFuncIndex 98

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
				(*(void(__thiscall**)(void*, const char*))(*(DWORD*)pRegisterBtn + 620))(pRegisterBtn, "Register"); // button->SetText() // before 23.12.23 pRegisterBtn + 604 // on 10.07.2024 pRegisterBtn + 612 // on 07.08.2024 pRegisterBtn + 620
				//(*(void(__thiscall**)(void*, const char*))(*(DWORD*)pImagePanel1 + 600))(pImagePanel1, "resource/login.tga"); // imagepanel->SetImage()
				(*(void(__thiscall**)(void*))(*(DWORD*)pLoginDlg + 840))(pLoginDlg); // loginDlg->DoModal() // before 23.12.23 pLoginDlg + 832 // on 10.07.2024 pLoginDlg + 840

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
			__except (EXCEPTION_EXECUTE_HANDLER)
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
	if (!dwBotManagerPtr)
	{
		MessageBox(NULL, "dwBotManagerPtr == NULL!!!", "Error", MB_OK);
		return;
	}
	g_pBotManager = **((CCSBotManager***)(dwBotManagerPtr));

	int side = 0;
	int argc = g_pEngine->Cmd_Argc();
	if (argc > 0)
	{
		side = atoi(g_pEngine->Cmd_Argv(1));
	}
	g_pBotManager->Bot_Add(side);
}

CreateHookClass(const char*, GetSSLProtocolName)
{
	return "None";
}

CreateHookClassType(void*, SocketConstructor, int, int a2, int a3, char a4)
{
	*(DWORD*)((int)ptr + 72) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 76) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 80) = (DWORD)g_pfnEVP_CIPHER_CTX_new();
	*(DWORD*)((int)ptr + 84) = (DWORD)g_pfnEVP_CIPHER_CTX_new();

	return g_pfnSocketConstructor(ptr, a2, a3, a4);
}

CreateHookClass(int, ReadPacket, char* outBuf, int len, unsigned short* outLen, bool initialMsg)
{
	int result = g_pfnReadPacket(ptr, outBuf, len, outLen, initialMsg);

	// this + 0x34 - read buf

	// 0 - got message, 4 - wrong header, 6 - idk, 7 - got less than 4 bytes, 8 - bad sequence
	if (!initialMsg && result == 0)
	{
		// create folder
		CreateDirectory("Packets", NULL);

		static int directoryCounter = 0;
		if (!directoryCounter)
		{
			while (true)
			{
				char directory[MAX_PATH];
				snprintf(directory, sizeof(directory), "Packets/%d", ++directoryCounter);

				DWORD dwAttr = GetFileAttributes(directory);
				if (dwAttr != 0xffffffff && (dwAttr & FILE_ATTRIBUTE_DIRECTORY))
				{
					continue;
				}

				CreateDirectory(directory, NULL);
				break;
			}
		}

		// write file
		unsigned char* buf = (unsigned char*)(outBuf);
		unsigned short dataLen = *outLen;

		static int packetCounter = 0;

		char filename[MAX_PATH];
		bool moreInfo = true;
		if (moreInfo)
			snprintf(filename, sizeof(filename), "Packets/%d/Packet_%d_ID_%d_%d.bin", directoryCounter, packetCounter++, buf[0], dataLen);
		else
			snprintf(filename, sizeof(filename), "Packets/%d/Packet_%d.bin", directoryCounter, packetCounter++);

		FILE* file = fopen(filename, "wb");
		fwrite(buf, dataLen, 1, file);
		fclose(file);
	}

	return result;
}

CreateHook(__cdecl, void, LogToErrorLog, char* pLogFile, int logFileId, char* fmt, int fmtLen, ...)
{
	char outputString[1024];

	va_list va;
	va_start(va, fmtLen);
	_vsnprintf_s(outputString, sizeof(outputString), fmt, va);
	outputString[1023] = 0;
	va_end(va);

	printf("[LogToErrorLog][%s.log] %s\n", pLogFile, outputString);

	g_pfnLogToErrorLog(pLogFile, logFileId, outputString, fmtLen);
}

CreateHook(WINAPI, void, OutputDebugStringA, LPCSTR lpOutString)
{
	printf("[OutputDebugString] %s\n", lpOutString);
}

CreateHook(__cdecl, int, HolePunch_GetUserSocketInfo, int userID, char* data)
{
	auto ret = g_pfnHolePunch_GetUserSocketInfo(userID, data);

	data[0] = 2; // unsafety method, since other places port are corrected

	short port = (short&)data[14];
	in_addr ip = (in_addr&)data[16];

	printf("[HolePunch_GetUserSocketInfo] ret: %d | UserID: %d, %s:%d\n", ret, userID, inet_ntoa(ip), ntohs(port));

	return ret;
}

void CreateDebugConsole()
{
	AllocConsole();

	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);

	SetConsoleTitleA("CSO launcher debug console");
	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);

	setlocale(LC_ALL, "");
}

DWORD WINAPI HookThread(LPVOID lpThreadParameter)
{
	hWnd = FindWindow(NULL, "Counter-Strike Nexon: Studio");
	oWndProc = (WNDPROC)SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)WndProc);

	if (!g_bUseOriginalServer)
	{
		while (!g_dwGameUIBase) // wait for gameui module
		{
			g_dwGameUIBase = (DWORD)GetModuleHandle("gameui.dll");
			Sleep(500);
		}
		g_dwGameUISize = GetModuleSize(GetModuleHandle("gameui.dll"));

		if (g_pEngine)
		{
			g_pChattingManager = g_pEngine->GetChatManager();
			if (!g_pChattingManager)
				MessageBox(NULL, "g_pChattingManager == NULL!!!", "Error", MB_OK);
		}

		CreateInterfaceFn gameui_factory = CaptureFactory("gameui.dll");
		CreateInterfaceFn vgui2_factory = CaptureFactory("vgui2.dll");
		g_pGameUI = (IGameUI*)(CaptureInterface(gameui_factory, GAMEUI_INTERFACE_VERSION));
		g_pPanel = (vgui::IPanel*)(CaptureInterface(vgui2_factory, VGUI_PANEL_INTERFACE_VERSION));
		VFTHook(g_pGameUI, 0, 7, GameUI_RunFrame, (void*&)g_pfnGameUI_RunFrame);

		while (!g_dwMpBase) // wait for mp.dll module
		{
			g_dwMpBase = (DWORD)GetModuleHandle("mp.dll");
			Sleep(500);
		}
		g_dwMpSize = GetModuleSize(GetModuleHandle("mp.dll"));

		{
			DWORD pushStr = 0;
			DWORD patchAddr = 0;
			BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

			// NOP IsDedi() function to load allstar Skill csv
			pushStr = FindPush(g_dwMpBase, g_dwMpBase + g_dwMpSize, (PCHAR)("Failed to Open AllStar_Skill-Dedi Table"));
			if (!pushStr)
				MessageBox(NULL, "AllStar_Skill_Patch == NULL!!!", "Error", MB_OK);
			else
			{
				patchAddr = pushStr - 0x1B;
				WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));
			}

			// NOP IsDedi() function to load allstar Status csv
			pushStr = FindPush(g_dwMpBase, g_dwMpBase + g_dwMpSize, (PCHAR)("Failed to Open AllStar_Status-Dedi Table"));
			if (!pushStr)
				MessageBox(NULL, "AllStar_Status_Patch == NULL!!!", "Error", MB_OK);
			else
			{
				patchAddr = pushStr - 0x1E;
				WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));
			}

			// NOP IsDedi() function to spawn zsht_item_box and zbsitem
			pushStr = FindPush(g_dwMpBase, g_dwMpBase + g_dwMpSize, (PCHAR)("zsht_item_box"), 3);
			if (!pushStr)
				MessageBox(NULL, "ZBS_ZSHT_ItemBox_Patch == NULL!!!", "Error", MB_OK);
			else
			{
				patchAddr = pushStr - 0x4C7;
				WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));
			}
		}

		if (g_pEngine)
			g_pEngine->pfnAddCommand("cso_bot_add", CSO_Bot_Add);
	}

	return TRUE;
}

void Init(HMODULE hEngineModule, HMODULE hFileSystemModule)
{
	printf("Init()\n");

	if (CommandLine()->CheckParm("-debug") || CommandLine()->CheckParm("-dev") || CommandLine()->CheckParm("+developer 1") || CommandLine()->CheckParm("-developer"))
		CreateDebugConsole();

	g_hEngineModule = hEngineModule;
	g_dwEngineBase = GetModuleBase(g_hEngineModule);
	g_dwEngineSize = GetModuleSize(g_hEngineModule);

	g_dwFileSystemBase = GetModuleBase(hFileSystemModule);
	g_dwFileSystemSize = GetModuleSize(hFileSystemModule);

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

	g_bRegister = CommandLine()->CheckParm("-register");
	if (CommandLine()->CheckParm("-login", &login) && login)
	{
		strncpy(g_pLogin, login, sizeof(g_pLogin));
		printf("g_pLogin = %s\n", g_pLogin);
	}
	if (CommandLine()->CheckParm("-password", &password) && password)
	{
		strncpy(g_pPassword, password, sizeof(g_pPassword));
		printf("g_pPassword = %s\n", g_pPassword);
	}

	g_bUseOriginalServer = CommandLine()->CheckParm("-useoriginalserver");
	g_bDumpMetadata = CommandLine()->CheckParm("-dumpmetadata");
	g_bIgnoreMetadata = CommandLine()->CheckParm("-ignoremetadata");
	g_bDumpQuest = CommandLine()->CheckParm("-dumpquest");
	g_bDumpUMsg = CommandLine()->CheckParm("-dumpumsg");
	g_bDumpAlarm = CommandLine()->CheckParm("-dumpalarm");
	g_bDumpItem = CommandLine()->CheckParm("-dumpitem");
	g_bDumpAll = CommandLine()->CheckParm("-dumpall");
	g_bDumpCrypt = CommandLine()->CheckParm("-dumpcrypt");
	g_bDisableAuthUI = CommandLine()->CheckParm("-disableauthui");
	g_bUseSSL = CommandLine()->CheckParm("-usessl");
	g_bWriteMetadata = CommandLine()->CheckParm("-writemetadata");
	g_bLoadDediCsvFromFile = CommandLine()->CheckParm("-loaddedicsvfromfile");
	g_bNoNGHook = CommandLine()->CheckParm("-nonghook");

	printf("g_pServerIP = %s, g_pServerPort = %s\n", g_pServerIP, g_pServerPort);
}

void Hook(HMODULE hEngineModule, HMODULE hFileSystemModule)
{
	Init(hEngineModule, hFileSystemModule);

	DWORD find = NULL;
	void* dummy = NULL;
	
	if (!g_bNoNGHook)
	{
		find = FindPattern(NGCLIENT_INIT_SIG_CSNZ, NGCLIENT_INIT_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "NGClient_Init == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, NGClient_Return1, dummy, dummy);

		find = FindPattern(NGCLIENT_QUIT_SIG_CSNZ, NGCLIENT_QUIT_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "NGClient_Quit == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, NGClient_Void, dummy, dummy);

		find = FindPattern(PACKET_HACK_SEND_SIG_CSNZ, PACKET_HACK_SEND_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_Hack_Send == NULL!!!", "Error", MB_OK);
		else
		{
			InlineHookFromCallOpcode((void*)find, NGClient_Void, dummy, dummy);
			InlineHookFromCallOpcode((void*)(find + 0x5), NGClient_Return1, dummy, dummy);
		}

		find = FindPattern(PACKET_HACK_PARSE_SIG_CSNZ, PACKET_HACK_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_Hack_Parse == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_Packet_Hack_Parse, dummy);
	}

	IATHook(g_hEngineModule, "nxgsm.dll", "InitializeGameLogManagerA", NXGSM_Dummy, dummy);
	IATHook(g_hEngineModule, "nxgsm.dll", "WriteStageLogA", NXGSM_WriteStageLogA, dummy);
	IATHook(g_hEngineModule, "nxgsm.dll", "WriteErrorLogA", NXGSM_WriteErrorLogA, dummy);
	IATHook(g_hEngineModule, "nxgsm.dll", "FinalizeGameLogManager", NXGSM_Dummy, dummy);
	IATHook(g_hEngineModule, "nxgsm.dll", "SetUserSN", NXGSM_Dummy, dummy);

	if (!g_bUseOriginalServer)
	{
		find = FindPattern(SOCKETMANAGER_SIG_CSNZ23, SOCKETMANAGER_MASK_CSNZ23, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "SocketManagerConstructor == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_SocketManagerConstructor, (void*&)g_pfnSocketManagerConstructor, dummy);

		find = FindPattern(SERVERCONNECT_SIG_CSNZ2019, SERVERCONNECT_MASK_CSNZ2019, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "ServerConnect == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_ServerConnect, (void*&)g_pfnServerConnect, dummy);

		find = FindPattern(HOLEPUNCH_SETSERVERINFO_SIG_CSNZ, HOLEPUNCH_SETSERVERINFO_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "HolePunch_SetServerInfo == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_HolePunch_SetServerInfo, (void*&)g_pfnHolePunch_SetServerInfo);

		find = FindPattern(HOLEPUNCH_GETUSERSOCKETINFO_SIG_CSNZ, HOLEPUNCH_GETUSERSOCKETINFO_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "HolePunch_GetUserSocketInfo == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_HolePunch_GetUserSocketInfo, (void*&)g_pfnHolePunch_GetUserSocketInfo);

		/*
		{
			DWORD pushStr = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("resource/zombi/ZombieSkillTable_Dedi.csv"));
			
			// read instruction opcode to know we found valid address
			int opcode = 0;
			ReadMemory((void*)(pushStr + 0xF), (BYTE*)&opcode, 1);

			if (opcode == 0xE8 && pushStr && InlineHookFromCallOpcode((void*)(pushStr + 0xF), CreateStringTable, (void*&)g_pfnCreateStringTable, dummy))
			{
				DWORD parseCsvCallAddr = (DWORD)dummy + 0x71 + 1; // 0x71
				g_pfnParseCSV = (tParseCSV)(parseCsvCallAddr + 4 + *(DWORD*)parseCsvCallAddr);

				// patch LoadZombieSkill function to load csv bypassing filesystem
				DWORD patchAddr = pushStr - 0x1A;
				BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
				WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));
			}
			else
			{
				MessageBox(NULL, "Failed to patch zombie skill table", "Error", MB_OK);
			}
		}
		*/

		{
			DWORD pushStr = 0;
			DWORD patchAddr = 0;

			// NOP dedi check on Zombie Skills
			pushStr = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("resource/zombi/ZombieSkillProperty_Dedi/ZombieSkillProperty_Crazy.csv"));
			if (!pushStr)
				MessageBox(NULL, "ZombieSkillProperty_Patch == NULL!!!", "Error", MB_OK);
			else
			{
				patchAddr = pushStr - 0x23;
				BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
				WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));
			}

			// NOP dedi check on Fire Bomb
			pushStr = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("resource/zombi/FireBombOption_Dedi.csv"));
			if (!pushStr)
				MessageBox(NULL, "FireBombOption_Patch == NULL!!!", "Error", MB_OK);
			else
			{
				patchAddr = pushStr - 0x8;
				BYTE patch2[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
				WriteMemory((void*)patchAddr, (BYTE*)patch2, sizeof(patch2));
			}

			find = FindPattern(CREATESTRINGTABLE_SIG_CSNZ, CREATESTRINGTABLE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
			if (!find)
				MessageBox(NULL, "CreateStringTable == NULL!!!", "Error", MB_OK);
			else
			{
				InlineHook((void*)find, Hook_CreateStringTable, (void*&)g_pfnCreateStringTable);

				DWORD parseCsvCallAddr = (DWORD)find + 0x71 + 1; // 0x71
				g_pfnParseCSV = (tParseCSV)(parseCsvCallAddr + 4 + *(DWORD*)parseCsvCallAddr);
			}

			find = FindPattern(LOADJSON_SIG_CSNZ, LOADJSON_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
			if (!find)
				MessageBox(NULL, "LoadJson == NULL!!!", "Error", MB_OK);
			else
				InlineHook((void*)find, Hook_LoadJson, (void*&)g_pfnLoadJson);
		}
	}

	find = FindPattern(LOGTOERRORLOG_SIG_CSNZ, LOGTOERRORLOG_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
	if (!find)
		MessageBox(NULL, "LogToErrorLog == NULL!!!", "Error", MB_OK);
	else
		InlineHook((void*)find, Hook_LogToErrorLog, (void*&)g_pfnLogToErrorLog);

	g_pEngine = (cl_enginefunc_t*)(PVOID) * (PDWORD)(FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, (PCHAR)("ScreenFade")) + 0x0D);
	if (!g_pEngine)
		MessageBox(NULL, "g_pEngine == NULL!!!", "Error", MB_OK);
	else
		// hook Pbuf_AddText to allow any cvar or cmd input from console
		g_pEngine->Pbuf_AddText = Pbuf_AddText;

	if (g_bDumpMetadata || g_bWriteMetadata || g_bIgnoreMetadata)
	{
		find = FindPattern(PACKET_METADATA_PARSE_SIG_CSNZ, PACKET_METADATA_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_Metadata_Parse == NULL!!!", "Error", MB_OK);
		else
		{
			InlineHook((void*)find, Hook_Packet_Metadata_Parse, (void*&)g_pfnPacket_Metadata_Parse);
			if (g_pEngine)
				g_pEngine->pfnAddCommand("metadata_requestall", Metadata_RequestAll);
		}
	}

	if (g_bDumpQuest)
	{
		find = FindPattern(PACKET_QUEST_PARSE_SIG_CSNZ, PACKET_QUEST_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_Quest_Parse == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_Packet_Quest_Parse, (void*&)g_pfnPacket_Quest_Parse);
	}

	if (g_bDumpUMsg)
	{
		find = FindPattern(PACKET_UMSG_PARSE_SIG_CSNZ, PACKET_UMSG_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_UMsg_Parse == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_Packet_UMsg_Parse, (void*&)g_pfnPacket_UMsg_Parse);
	}

	if (g_bDumpAlarm)
	{
		find = FindPattern(PACKET_ALARM_PARSE_SIG_CSNZ, PACKET_ALARM_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_Alarm_Parse == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_Packet_Alarm_Parse, (void*&)g_pfnPacket_Alarm_Parse);
	}

	if (g_bDumpItem)
	{
		find = FindPattern(PACKET_ITEM_PARSE_SIG_CSNZ, PACKET_ITEM_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_Item_Parse == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_Packet_Item_Parse, (void*&)g_pfnPacket_Item_Parse);
	}

	if (g_bDumpCrypt)
	{
		find = FindPattern(PACKET_CRYPT_PARSE_SIG_CSNZ, PACKET_CRYPT_PARSE_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "Packet_Crypt_Parse == NULL!!!", "Error", MB_OK);
		else
			InlineHook((void*)find, Hook_Packet_Crypt_Parse, (void*&)g_pfnPacket_Crypt_Parse);
	}

	if (g_bDumpAll)
	{
		find = FindPattern(READPACKET_SIG_CSNZ, READPACKET_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "ReadPacket == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_ReadPacket, (void*&)g_pfnReadPacket, dummy);
	}

	// patch launcher name in hw.dll to fix annoying message box (length of launcher filename must be < original name)
	find = FindPattern("cstrike-online.exe", strlen("cstrike-online.exe"), g_dwEngineBase, g_dwEngineBase + g_dwEngineSize);
	if (!find)
		MessageBox(NULL, "LauncherName_Patch == NULL!!!", "Error", MB_OK);
	else
		WriteMemory((void*)find, (BYTE*)"CSOLauncher.exe", strlen("CSOLauncher.exe") + 1);

	// patch 100 fps limit
	find = FindPush(g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, "%3i fps -- host(%3.0f) sv(%3.0f) cl(%3.0f) gfx(%3.0f) snd(%3.0f) ents(%d)\n", 2);
	if (!find)
		MessageBox(NULL, "100Fps_Patch == NULL!!!", "Error", MB_OK);
	else
	{
		DWORD patchAddr = find - 0x4DA;
		BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		WriteMemory((void*)patchAddr, (BYTE*)patch, sizeof(patch));
	}

	if (!g_bUseOriginalServer && !g_bUseSSL)
	{
		// hook GetSSLProtocolName to make Crypt work
		find = FindPattern(GETSSLPROTOCOLNAME_SIG_CSNZ, GETSSLPROTOCOLNAME_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "GetSSLProtocolName == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_GetSSLProtocolName, (void*&)g_pfnGetSSLProtocolName, dummy);

		// hook SocketConstructor to create ctx objects
		find = FindPattern(SOCKETCONSTRUCTOR_SIG_CSNZ, SOCKETCONSTRUCTOR_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "SocketConstructor == NULL!!!", "Error", MB_OK);
		else
			InlineHookFromCallOpcode((void*)find, Hook_SocketConstructor, (void*&)g_pfnSocketConstructor, dummy);

		find = FindPattern(EVP_CIPHER_CTX_NEW_SIG_CSNZ, EVP_CIPHER_CTX_NEW_MASK_CSNZ, g_dwEngineBase, g_dwEngineBase + g_dwEngineSize, NULL);
		if (!find)
			MessageBox(NULL, "EVP_CIPHER_CTX_new == NULL!!!", "Error", MB_OK);
		else
		{
			DWORD dwCreateCtxAddr = find + 1;
			g_pfnEVP_CIPHER_CTX_new = (tEVP_CIPHER_CTX_new)(dwCreateCtxAddr + 4 + *(DWORD*)dwCreateCtxAddr);
		}
	}

	// create thread to wait for other modules
	CreateThread(NULL, 0, HookThread, NULL, 0, 0);
}

void Unhook()
{
	FreeAllHook();
}