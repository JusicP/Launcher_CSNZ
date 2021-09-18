#pragma once

class CChattingManager
{
public:
	virtual int ClanMsg(int a1, int a2);
	virtual int Unk1(int unk, wchar_t *msg);
	virtual void PrintToChat(int chatType, wchar_t* message);
	virtual void Unk2();
	virtual void Unk3();
	virtual void Unk4();
	virtual void Unk5();
	virtual void Unk6();
	virtual void Unk7();
	virtual void Unk8();
	virtual wchar_t* FormatChatMsg(wchar_t* a1, wchar_t* a2, bool a3, int chatType);
	virtual void Unk10();
	virtual void Unk11();
	virtual void Unk12();
	virtual void Unk13();
	virtual void Unk14();
	virtual void Unk15();
	virtual void Unk16(wchar_t* message);
	virtual void Unk17();
	virtual void Unk18();
	virtual void Unk19();
	virtual void Unk20();
	virtual void PrintToChatLog(wchar_t* message, int color = 0);

};
