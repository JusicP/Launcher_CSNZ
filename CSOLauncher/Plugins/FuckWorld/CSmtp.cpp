#include "CSmtp.h"
#include "base64.h"
#include "openssl/err.h"

#include <cassert>

using namespace std;

#ifndef LINUX
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")
#endif

Command_Entry command_list[] =
{
	{ command_INIT, 0, 5 * 60, 220, ECSmtp::SERVER_NOT_RESPONDING },
	{ command_EHLO, 5 * 60, 5 * 60, 250, ECSmtp::COMMAND_EHLO },
	{ command_AUTHPLAIN, 5 * 60, 5 * 60, 235, ECSmtp::COMMAND_AUTH_PLAIN },
	{ command_AUTHLOGIN, 5 * 60, 5 * 60, 334, ECSmtp::COMMAND_AUTH_LOGIN },
	{ command_AUTHCRAMMD5, 5 * 60, 5 * 60, 334, ECSmtp::COMMAND_AUTH_CRAMMD5 },
	{ command_AUTHDIGESTMD5, 5 * 60, 5 * 60, 334, ECSmtp::COMMAND_AUTH_DIGESTMD5 },
	{ command_DIGESTMD5, 5 * 60, 5 * 60, 335, ECSmtp::COMMAND_DIGESTMD5 },
	{ command_USER, 5 * 60, 5 * 60, 334, ECSmtp::UNDEF_XYZ_RESPONSE },
	{ command_PASSWORD, 5 * 60, 5 * 60, 235, ECSmtp::BAD_LOGIN_PASS },
	{ command_MAILFROM, 5 * 60, 5 * 60, 250, ECSmtp::COMMAND_MAIL_FROM },
	{ command_RCPTTO, 5 * 60, 5 * 60, 250, ECSmtp::COMMAND_RCPT_TO },
	{ command_DATA, 5 * 60, 2 * 60, 354, ECSmtp::COMMAND_DATA },
	{ command_DATABLOCK, 3 * 60, 0, 0, ECSmtp::COMMAND_DATABLOCK },
	{ command_DATAEND, 3 * 60, 10 * 60, 250, ECSmtp::MSG_BODY_ERROR },
	{ command_QUIT, 5 * 60, 5 * 60, 221, ECSmtp::COMMAND_QUIT },
	{ command_STARTTLS, 5 * 60, 5 * 60, 220, ECSmtp::COMMAND_EHLO_STARTTLS }
};

Command_Entry *FindCommandEntry(SMTP_COMMAND command)
{
	Command_Entry *pEntry = NULL;

	for (size_t i = 0; i < sizeof(command_list) / sizeof(command_list[0]); ++i)
	{
		if (command_list[i].command == command)
		{
			pEntry = &command_list[i];
			break;
		}
	}

	assert(pEntry != NULL);
	return pEntry;
}

bool IsKeywordSupported(const char *response, const char *keyword)
{
	assert(response != NULL && keyword != NULL);

	if (response == NULL || keyword == NULL)
		return false;

	int res_len = strlen(response);
	int key_len = strlen(keyword);

	if (res_len < key_len)
		return false;

	int pos = 0;

	for (; pos < res_len - key_len + 1; ++pos)
	{
		if (_strnicmp(keyword, response+pos, key_len) == 0)
		{
			if (pos > 0 && (response[pos - 1] == '-' || response[pos - 1] == ' ' || response[pos - 1] == '='))
			{
				if (pos+key_len < res_len)
				{
					if (response[pos+key_len] == ' ' || response[pos+key_len] == '=')
					{
						return true;
					}
					else if (pos+key_len+1 < res_len)
					{
						if (response[pos+key_len] == '\r' && response[pos+key_len+1] == '\n')
						{
							return true;
						}
					}
				}
			}
		}
	}

	return false;
}

unsigned char *CharToUnsignedChar(const char *strIn)
{
	unsigned char *strOut;
	unsigned long length, i;

	length = strlen(strIn);
	strOut = new unsigned char[length + 1];

	if (!strOut)
		return NULL;

	for (i = 0; i < length; i++)
		strOut[i] = (unsigned char)strIn[i];

	strOut[length] = '\0';
	return strOut;
}

CSmtp::CSmtp(void)
{
	hSocket = INVALID_SOCKET;
	m_bConnected = false;
	m_iXPriority = XPRIORITY_NORMAL;
	m_iSMTPSrvPort = 0;
	m_bAuthenticate = true;

#ifndef LINUX
	WSADATA wsaData;
	WORD wVer = MAKEWORD(2, 2);

	if (WSAStartup(wVer, &wsaData) != NO_ERROR)
		throw ECSmtp(ECSmtp::WSA_STARTUP);

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		WSACleanup();
		throw ECSmtp(ECSmtp::WSA_VER);
	}
#endif
	char hostname[255];

	if (gethostname((char *)&hostname, 255) == SOCKET_ERROR)
		throw ECSmtp(ECSmtp::WSA_HOSTNAME);

	m_sLocalHostName = hostname;

	if ((RecvBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

	if ((SendBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

	m_type = NO_SECURITY;
	m_ctx = NULL;
	m_ssl = NULL;
	m_bHTML = false;
	m_bReadReceipt = false;
	m_sCharSet = "US-ASCII";
}

CSmtp::~CSmtp(void)
{
	if (m_bConnected)
		DisconnectRemoteServer();

	if (SendBuf)
	{
		delete [] SendBuf;
		SendBuf = NULL;
	}

	if (RecvBuf)
	{
		delete [] RecvBuf;
		RecvBuf = NULL;
	}

	CleanupOpenSSL();

#ifndef LINUX
	WSACleanup();
#endif
}

void CSmtp::AddAttachment(const char *Path)
{
	assert(Path);
	Attachments.insert(Attachments.end(), Path);
}

void CSmtp::AddRecipient(const char *email, const char *name)
{
	if (!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	recipient.Mail = email;

	if (name != NULL)
		recipient.Name = name;
	else
		recipient.Name.empty();

	Recipients.insert(Recipients.end(), recipient); 
}

void CSmtp::AddCCRecipient(const char *email, const char *name)
{
	if (!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	recipient.Mail = email;

	if (name != NULL)
		recipient.Name = name;
	else
		recipient.Name.empty();

	CCRecipients.insert(CCRecipients.end(), recipient);
}

void CSmtp::AddBCCRecipient(const char *email, const char *name)
{
	if (!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	recipient.Mail = email;

	if (name != NULL)
		recipient.Name = name;
	else
		recipient.Name.empty();

	BCCRecipients.insert(BCCRecipients.end(), recipient);
}

void CSmtp::AddMsgLine(const char *Text)
{
	MsgBody.insert(MsgBody.end(), Text);
}

void CSmtp::DelMsgLine(unsigned int Line)
{
	if (Line >= MsgBody.size())
		throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);

	MsgBody.erase(MsgBody.begin()+Line);
}

void CSmtp::DelRecipients(void)
{
	Recipients.clear();
}

void CSmtp::DelBCCRecipients(void)
{
	BCCRecipients.clear();
}

void CSmtp::DelCCRecipients(void)
{
	CCRecipients.clear();
}

void CSmtp::DelMsgLines(void)
{
	MsgBody.clear();
}

void CSmtp::DelAttachments(void)
{
	Attachments.clear();
}

void CSmtp::ModMsgLine(unsigned int Line, const char *Text)
{
	if (Text)
	{
		if (Line >= MsgBody.size())
			throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);

		MsgBody.at(Line) = std::string(Text);
	}
}

void CSmtp::ClearMessage(void)
{
	DelRecipients();
	DelBCCRecipients();
	DelCCRecipients();
	DelAttachments();
	DelMsgLines();
}

void CSmtp::Send(void)
{
	unsigned int i, rcpt_count, res, FileId;
	char *FileBuf = NULL;
	FILE* hFile = NULL;
	unsigned long int FileSize, TotalSize, MsgPart;
	string FileName, EncodedFileName;
	string::size_type pos;

	if (hSocket==INVALID_SOCKET)
	{
		if (!ConnectRemoteServer(m_sSMTPSrvName.c_str(), m_iSMTPSrvPort, m_type, m_bAuthenticate))
			throw ECSmtp(ECSmtp::WSA_INVALID_SOCKET);
	}

	try
	{
		if ((FileBuf = new char[55]) == NULL)
			throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

		TotalSize = 0;

		for (FileId = 0; FileId < Attachments.size(); FileId++)
		{
			hFile = fopen(Attachments[FileId].c_str(), "rb");

			if (hFile == NULL)
				throw ECSmtp(ECSmtp::FILE_NOT_EXIST);

			fseek(hFile, 0, SEEK_END);
			FileSize = ftell(hFile);
			TotalSize += FileSize;

			if (TotalSize / 1024 > MSG_SIZE_IN_MB * 1024)
				throw ECSmtp(ECSmtp::MSG_TOO_BIG);

			fclose(hFile);
		}

		if (!m_sMailFrom.size())
			throw ECSmtp(ECSmtp::UNDEF_MAIL_FROM);

		Command_Entry *pEntry = FindCommandEntry(command_MAILFROM);
		snprintf(SendBuf, BUFFER_SIZE, "MAIL FROM:<%s>\r\n", m_sMailFrom.c_str());
		SendData(pEntry);
		ReceiveResponse(pEntry);

		if (!(rcpt_count = Recipients.size()))
			throw ECSmtp(ECSmtp::UNDEF_RECIPIENTS);

		pEntry = FindCommandEntry(command_RCPTTO);

		for (i = 0; i < Recipients.size(); i++)
		{
			snprintf(SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (Recipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}

		for (i = 0; i < CCRecipients.size(); i++)
		{
			snprintf(SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (CCRecipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}

		for (i = 0; i < BCCRecipients.size(); i++)
		{
			snprintf(SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (BCCRecipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}

		pEntry = FindCommandEntry(command_DATA);

		snprintf(SendBuf, BUFFER_SIZE, "DATA\r\n");
		SendData(pEntry);
		ReceiveResponse(pEntry);

		pEntry = FindCommandEntry(command_DATABLOCK);

		FormatHeader(SendBuf);
		SendData(pEntry);

		if (GetMsgLines())
		{
			for (i = 0; i < GetMsgLines(); i++)
			{
				snprintf(SendBuf, BUFFER_SIZE, "%s\r\n", GetMsgLineText(i));
				SendData(pEntry);
			}
		}
		else
		{
			snprintf(SendBuf, BUFFER_SIZE, "%s\r\n", " ");
			SendData(pEntry);
		}

		for (FileId = 0; FileId < Attachments.size(); FileId++)
		{
#ifndef LINUX
			pos = Attachments[FileId].find_last_of("\\");
#else
			pos = Attachments[FileId].find_last_of("/");
#endif
			if (pos == string::npos)
				continue;

			FileName = Attachments[FileId].substr(pos + 1);

			EncodedFileName = "=?UTF-8?B?";
			EncodedFileName += base64_encode((unsigned char *)FileName.c_str(), FileName.size());
			EncodedFileName += "?=";

			snprintf(SendBuf, BUFFER_SIZE, "--%s\r\n", BOUNDARY_TEXT);
			strcat(SendBuf, "Content-Type: application/x-msdownload; name=\"");
			strcat(SendBuf, EncodedFileName.c_str());
			strcat(SendBuf, "\"\r\n");
			strcat(SendBuf, "Content-Transfer-Encoding: base64\r\n");
			strcat(SendBuf, "Content-Disposition: attachment; filename=\"");
			strcat(SendBuf, EncodedFileName.c_str());
			strcat(SendBuf, "\"\r\n");
			strcat(SendBuf, "\r\n");

			SendData(pEntry);

			hFile = fopen(Attachments[FileId].c_str(), "rb");

			if (hFile == NULL)
				throw ECSmtp(ECSmtp::FILE_NOT_EXIST);

			fseek(hFile, 0, SEEK_END);
			FileSize = ftell(hFile);
			fseek (hFile,0,SEEK_SET);

			MsgPart = 0;

			for (i = 0; i < FileSize / 54 + 1; i++)
			{
				res = fread(FileBuf, sizeof(char), 54, hFile);
				MsgPart ? strcat(SendBuf, base64_encode(reinterpret_cast<const unsigned char *>(FileBuf), res).c_str()) : strcpy(SendBuf, base64_encode(reinterpret_cast<const unsigned char *>(FileBuf), res).c_str());
				strcat(SendBuf, "\r\n");
				MsgPart += res + 2;

				if (MsgPart >= BUFFER_SIZE / 2)
				{
					MsgPart = 0;
					SendData(pEntry);
				}
			}

			if (MsgPart)
				SendData(pEntry);

			fclose(hFile);
		}

		delete [] FileBuf;

		if (Attachments.size())
		{
			snprintf(SendBuf, BUFFER_SIZE, "\r\n--%s--\r\n",BOUNDARY_TEXT);
			SendData(pEntry);
		}

		pEntry = FindCommandEntry(command_DATAEND);

		snprintf(SendBuf, BUFFER_SIZE, "\r\n.\r\n");
		SendData(pEntry);
		ReceiveResponse(pEntry);
	}
	catch (const ECSmtp &)
	{
		DisconnectRemoteServer();
		throw;
	}
}

bool CSmtp::ConnectRemoteServer(const char *szServer, const unsigned short nPort_, SMTP_SECURITY_TYPE securityType, bool authenticate, const char *login, const char *password)
{
	unsigned short nPort = 0;
	LPSERVENT lpServEnt;
	SOCKADDR_IN sockAddr;
	unsigned long ul = 1;
	fd_set fdwrite,fdexcept;
	timeval timeout;
	int res = 0;

	try
	{
		timeout.tv_sec = TIME_IN_SEC;
		timeout.tv_usec = 0;

		hSocket = INVALID_SOCKET;

		if ((hSocket = socket(PF_INET, SOCK_STREAM,0)) == INVALID_SOCKET)
			throw ECSmtp(ECSmtp::WSA_INVALID_SOCKET);

		if (nPort_ != 0)
		{
			nPort = htons(nPort_);
		}
		else
		{
			lpServEnt = getservbyname("mail", 0);

			if (lpServEnt == NULL)
				nPort = htons(25);
			else 
				nPort = lpServEnt->s_port;
		}

		sockAddr.sin_family = AF_INET;
		sockAddr.sin_port = nPort;

		if ((sockAddr.sin_addr.s_addr = inet_addr(szServer)) == INADDR_NONE)
		{
			LPHOSTENT host = gethostbyname(szServer);

			if (host)
			{
				memcpy(&sockAddr.sin_addr, host->h_addr_list[0], host->h_length);
			}
			else
			{
#ifdef LINUX
				close(hSocket);
#else
				closesocket(hSocket);
#endif
				throw ECSmtp(ECSmtp::WSA_GETHOSTBY_NAME_ADDR);
			}				
		}

#ifdef LINUX
		if (ioctl(hSocket, FIONBIO, (unsigned long *)&ul) == SOCKET_ERROR)
#else
		if (ioctlsocket(hSocket, FIONBIO, (unsigned long *)&ul) == SOCKET_ERROR)
#endif
		{
#ifdef LINUX
			close(hSocket);
#else
			closesocket(hSocket);
#endif
			throw ECSmtp(ECSmtp::WSA_IOCTLSOCKET);
		}

		if (connect(hSocket, (LPSOCKADDR)&sockAddr, sizeof(sockAddr)) == SOCKET_ERROR)
		{
#ifdef LINUX
			if (errno != EINPROGRESS)
#else
			if (WSAGetLastError() != WSAEWOULDBLOCK)
#endif
			{
#ifdef LINUX
				close(hSocket);
#else
				closesocket(hSocket);
#endif
				throw ECSmtp(ECSmtp::WSA_CONNECT);
			}
		}
		else
			return true;

		while (true)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdexcept);

			FD_SET(hSocket, &fdwrite);
			FD_SET(hSocket, &fdexcept);

			if ((res = select(hSocket + 1,NULL, &fdwrite, &fdexcept, &timeout)) == SOCKET_ERROR)
			{
#ifdef LINUX
				close(hSocket);
#else
				closesocket(hSocket);
#endif
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}

			if (!res)
			{
#ifdef LINUX
				close(hSocket);
#else
				closesocket(hSocket);
#endif
				throw ECSmtp(ECSmtp::SELECT_TIMEOUT);
			}

			if (res && FD_ISSET(hSocket, &fdwrite))
				break;

			if (res && FD_ISSET(hSocket, &fdexcept))
			{
#ifdef LINUX
				close(hSocket);
#else
				closesocket(hSocket);
#endif
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}
		}

		FD_CLR(hSocket, &fdwrite);
		FD_CLR(hSocket, &fdexcept);

		if (securityType!=DO_NOT_SET)
			SetSecurityType(securityType);

		if (GetSecurityType() == USE_TLS || GetSecurityType() == USE_SSL)
		{
			InitOpenSSL();

			if (GetSecurityType() == USE_SSL)
				OpenSSLConnect();
		}

		Command_Entry *pEntry = FindCommandEntry(command_INIT);
		ReceiveResponse(pEntry);

		SayHello();

		if (GetSecurityType() == USE_TLS)
		{
			StartTls();
			SayHello();
		}

		if (authenticate && IsKeywordSupported(RecvBuf, "AUTH") == true)
		{
			if (login)
				SetLogin(login);

			if (!m_sLogin.size())
				throw ECSmtp(ECSmtp::UNDEF_LOGIN);

			if (password)
				SetPassword(password);

			if (!m_sPassword.size())
				throw ECSmtp(ECSmtp::UNDEF_PASSWORD);

			if (IsKeywordSupported(RecvBuf, "LOGIN") == true)
			{
				pEntry = FindCommandEntry(command_AUTHLOGIN);
				snprintf(SendBuf, BUFFER_SIZE, "AUTH LOGIN\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				std::string encoded_login = base64_encode(reinterpret_cast<const unsigned char *>(m_sLogin.c_str()), m_sLogin.size());
				pEntry = FindCommandEntry(command_USER);
				snprintf(SendBuf, BUFFER_SIZE, "%s\r\n",encoded_login.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);

				std::string encoded_password = base64_encode(reinterpret_cast<const unsigned char *>(m_sPassword.c_str()), m_sPassword.size());
				pEntry = FindCommandEntry(command_PASSWORD);
				snprintf(SendBuf, BUFFER_SIZE, "%s\r\n",encoded_password.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if (IsKeywordSupported(RecvBuf, "PLAIN") == true)
			{
				pEntry = FindCommandEntry(command_AUTHPLAIN);
				snprintf(SendBuf, BUFFER_SIZE, "%s^%s^%s", m_sLogin.c_str(), m_sLogin.c_str(), m_sPassword.c_str());

				unsigned int length = strlen(SendBuf);
				unsigned char *ustrLogin = CharToUnsignedChar(SendBuf);

				for (unsigned int i = 0; i < length; i++)
				{
					if (ustrLogin[i] == 94)
						ustrLogin[i] = 0;
				}

				std::string encoded_login = base64_encode(ustrLogin, length);
				delete [] ustrLogin;
				snprintf(SendBuf, BUFFER_SIZE, "AUTH PLAIN %s\r\n", encoded_login.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if (IsKeywordSupported(RecvBuf, "CRAM-MD5") == true)
			{
				pEntry = FindCommandEntry(command_AUTHCRAMMD5);
				snprintf(SendBuf, BUFFER_SIZE, "AUTH CRAM-MD5\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				std::string encoded_challenge = RecvBuf;
				encoded_challenge = encoded_challenge.substr(4);
				std::string decoded_challenge = base64_decode(encoded_challenge);

				unsigned char *ustrChallenge = CharToUnsignedChar(decoded_challenge.c_str());
				unsigned char *ustrPassword = CharToUnsignedChar(m_sPassword.c_str());

				if (!ustrChallenge || !ustrPassword)
					throw ECSmtp(ECSmtp::BAD_LOGIN_PASSWORD);

				int passwordLength = m_sPassword.size();

				if (passwordLength > 64)
				{
					MD5Context_t md5password;
					memset(&md5password, 0, sizeof(md5password));
					MD5Update(&md5password, ustrPassword, passwordLength);
					MD5Final(ustrPassword, &md5password);
					passwordLength = 16;
				}

				unsigned char ipad[65], opad[65];
				memset(ipad, 0, 64);
				memset(opad, 0, 64);
				memcpy(ipad, ustrPassword, passwordLength);
				memcpy(opad, ustrPassword, passwordLength);

				for (int i = 0; i<64; i++)
				{
					ipad[i] ^= 0x36;
					opad[i] ^= 0x5c;
				}

				unsigned char ustrResult[16], ustrResult2[16];
				char hexDigest[33];

				MD5Context_t md5pass1;
				memset(&md5pass1, 0, sizeof(md5pass1));
				MD5Update(&md5pass1, ipad, 64);
				MD5Update(&md5pass1, ustrChallenge, decoded_challenge.size());
				MD5Final(ustrResult, &md5pass1);

				MD5Context_t md5pass2;
				memset(&md5pass2, 0, sizeof(md5pass2));
				MD5Update(&md5pass2, opad, 64);
				MD5Update(&md5pass2, ustrResult, 16);
				MD5Final(ustrResult2, &md5pass2);

				for (int i = 0; i < 16; i++)
					sprintf(&hexDigest[i * 2], "%02x", ustrResult2[i]);

				hexDigest[32] = '\0';
				decoded_challenge = hexDigest;

				delete [] ustrChallenge;
				delete [] ustrPassword;

				decoded_challenge = m_sLogin + " " + decoded_challenge;
				encoded_challenge = base64_encode(reinterpret_cast<const unsigned char *>(decoded_challenge.c_str()),decoded_challenge.size());

				snprintf(SendBuf, BUFFER_SIZE, "%s\r\n", encoded_challenge.c_str());
				pEntry = FindCommandEntry(command_PASSWORD);
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if (IsKeywordSupported(RecvBuf, "DIGEST-MD5") == true)
			{
				pEntry = FindCommandEntry(command_DIGESTMD5);
				snprintf(SendBuf, BUFFER_SIZE, "AUTH DIGEST-MD5\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				std::string encoded_challenge = RecvBuf;
				encoded_challenge = encoded_challenge.substr(4);
				std::string decoded_challenge = base64_decode(encoded_challenge);

				int find = decoded_challenge.find("nonce");

				if (find < 0)
					throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);

				std::string nonce = decoded_challenge.substr(find + 7);
				find = nonce.find("\"");

				if (find < 0)
					throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);

				nonce = nonce.substr(0, find);

				std::string realm;
				find = decoded_challenge.find("realm");

				if (find >= 0)
				{
					realm = decoded_challenge.substr(find + 7);
					find = realm.find("\"");

					if (find < 0)
						throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);

					realm = realm.substr(0, find);
				}

				char cnonce[17], nc[9];
				snprintf(cnonce, 17, "%x", (unsigned int)time(NULL));

				snprintf(nc, 9, "%08d", 1);

				std::string qop = "auth";
#ifdef __linux__
				socklen_t len;
#else
				int len;
#endif
				struct sockaddr addr;
				len = sizeof addr;

				if (!getpeername(hSocket, (struct sockaddr*)&addr, &len))
					throw ECSmtp(ECSmtp::BAD_SERVER_NAME);

				struct sockaddr_in *s = (struct sockaddr_in *)&addr;
				std::string uri =inet_ntoa(s->sin_addr);
				uri = "smtp/" + uri;

				unsigned char *ustrRealm = CharToUnsignedChar(realm.c_str());
				unsigned char *ustrUsername = CharToUnsignedChar(m_sLogin.c_str());
				unsigned char *ustrPassword = CharToUnsignedChar(m_sPassword.c_str());
				unsigned char *ustrNonce = CharToUnsignedChar(nonce.c_str());
				unsigned char *ustrCNonce = CharToUnsignedChar(cnonce);
				unsigned char *ustrUri = CharToUnsignedChar(uri.c_str());
				unsigned char *ustrNc = CharToUnsignedChar(nc);
				unsigned char *ustrQop = CharToUnsignedChar(qop.c_str());

				if (!ustrRealm || !ustrUsername || !ustrPassword || !ustrNonce || !ustrCNonce || !ustrUri || !ustrNc || !ustrQop)
					throw ECSmtp(ECSmtp::BAD_LOGIN_PASSWORD);

				unsigned char ua1[16], ua2[16], ua3[16], ua4[16];
				char a1[33], a2[33];

				MD5Context_t md5a1a;
				memset(&md5a1a, 0, sizeof(md5a1a));
				MD5Update(&md5a1a, ustrUsername, m_sLogin.size());
				MD5Update(&md5a1a, (unsigned char *)":", 1);
				MD5Update(&md5a1a, ustrRealm, realm.size());
				MD5Update(&md5a1a, (unsigned char *)":", 1);
				MD5Update(&md5a1a, ustrPassword, m_sPassword.size());
				MD5Final(ua1, &md5a1a);

				MD5Context_t md5a1b;
				memset(&md5a1b, 0, sizeof(md5a1b));
				MD5Update(&md5a1b, ua1, 16);
				MD5Update(&md5a1b, (unsigned char *)":", 1);
				MD5Update(&md5a1b, ustrNonce, nonce.size());
				MD5Update(&md5a1b, (unsigned char *)":", 1);
				MD5Update(&md5a1b, ustrCNonce, strlen(cnonce));
				MD5Final(ua2, &md5a1b);

				for (int i = 0; i < 16; i++)
					sprintf(&a1[i * 2], "%02x", ua2[i]);

				a1[32] = '\0';

				MD5Context_t md5a2;
				memset(&md5a2, 0, sizeof(md5a2));
				MD5Update(&md5a2, (unsigned char *) "AUTHENTICATE:", 13);
				MD5Update(&md5a2, ustrUri, uri.size());
				MD5Final(ua3, &md5a2);

				for (int i = 0; i < 16; i++)
					sprintf(&a2[i * 2], "%02x", ua3[i]);

				a2[32] = '\0';

				unsigned char *_ua1 = CharToUnsignedChar(a1);
				unsigned char *_ua2 = CharToUnsignedChar(a2);
				char hexDigest[33];

				MD5Context_t md5;
				memset(&md5, 0, sizeof(md5));
				MD5Update(&md5, ua1, 32);
				MD5Update(&md5, (unsigned char *)":", 1);
				MD5Update(&md5, ustrNonce, nonce.size());
				MD5Update(&md5, (unsigned char *)":", 1);
				MD5Update(&md5, ustrNc, strlen(nc));
				MD5Update(&md5, (unsigned char *)":", 1);
				MD5Update(&md5, ustrCNonce, strlen(cnonce));
				MD5Update(&md5, (unsigned char *)":", 1);
				MD5Update(&md5, ustrQop, qop.size());
				MD5Update(&md5, (unsigned char *)":", 1);
				MD5Update(&md5, ua2, 32);
				MD5Final(ua4, &md5);

				for (int i = 0; i < 16; i++)
					sprintf(&hexDigest[i * 2], "%02x", ua4[i]);

				hexDigest[32] = '\0';
				decoded_challenge = hexDigest;

				delete [] ustrRealm;
				delete [] ustrUsername;
				delete [] ustrPassword;
				delete [] ustrNonce;
				delete [] ustrCNonce;
				delete [] ustrUri;
				delete [] ustrNc;
				delete [] ustrQop;

				if (strstr(RecvBuf, "charset") >= 0)
					snprintf(SendBuf, BUFFER_SIZE, "charset=utf-8,username=\"%s\"", m_sLogin.c_str());
				else
					snprintf(SendBuf, BUFFER_SIZE, "username=\"%s\"", m_sLogin.c_str());

				if (!realm.empty())
				{
					snprintf(RecvBuf, BUFFER_SIZE, ",realm=\"%s\"", realm.c_str());
					strcat(SendBuf, RecvBuf);
				}

				snprintf(RecvBuf, BUFFER_SIZE, ",nonce=\"%s\"", nonce.c_str());
				strcat(SendBuf, RecvBuf);
				snprintf(RecvBuf, BUFFER_SIZE, ",nc=%s", nc);
				strcat(SendBuf, RecvBuf);
				snprintf(RecvBuf, BUFFER_SIZE, ",cnonce=\"%s\"", cnonce);
				strcat(SendBuf, RecvBuf);
				snprintf(RecvBuf, BUFFER_SIZE, ",digest-uri=\"%s\"", uri.c_str());
				strcat(SendBuf, RecvBuf);
				snprintf(RecvBuf, BUFFER_SIZE, ",response=%s", decoded_challenge.c_str());
				strcat(SendBuf, RecvBuf);
				snprintf(RecvBuf, BUFFER_SIZE, ",qop=%s", qop.c_str());
				strcat(SendBuf, RecvBuf);

				unsigned char *ustrDigest = CharToUnsignedChar(SendBuf);
				encoded_challenge = base64_encode(ustrDigest, strlen(SendBuf));

				delete [] ustrDigest;

				snprintf(SendBuf, BUFFER_SIZE, "%s\r\n", encoded_challenge.c_str());
				pEntry = FindCommandEntry(command_DIGESTMD5);
				SendData(pEntry);
				ReceiveResponse(pEntry);

				snprintf(SendBuf, BUFFER_SIZE, "\r\n");
				pEntry = FindCommandEntry(command_PASSWORD);
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else
				throw ECSmtp(ECSmtp::LOGIN_NOT_SUPPORTED);
		}
	}
	catch (const ECSmtp&)
	{
		if (RecvBuf[0] == '5' && RecvBuf[1] == '3' && RecvBuf[2] == '0')
			m_bConnected = false;

		DisconnectRemoteServer();
		throw;
		return false;
	}

	return true;
}

void CSmtp::DisconnectRemoteServer(void)
{
	if (m_bConnected)
		SayQuit();

	if (hSocket)
	{
#ifdef LINUX
		close(hSocket);
#else
		closesocket(hSocket);
#endif
	}

	hSocket = INVALID_SOCKET;
}

int CSmtp::SmtpXYZdigits(void)
{
	assert(RecvBuf);

	if (RecvBuf == NULL)
		return 0;

	return (RecvBuf[0] - '0') * 100 + (RecvBuf[1] - '0') * 10 + RecvBuf[2] - '0';
}

void CSmtp::FormatHeader(char *header)
{
	char month[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	size_t i;
	std::string to;
	std::string cc;
	std::string bcc;
	time_t rawtime;
	struct tm *timeinfo;

	if (time(&rawtime) > 0)
		timeinfo = localtime(&rawtime);
	else
		throw ECSmtp(ECSmtp::TIME_ERROR);

	if (Recipients.size())
	{
		for (i = 0; i < Recipients.size(); i++)
		{
			if (i > 0)
				to.append(", ");

			to += Recipients[i].Name;
			to.append("<");
			to += Recipients[i].Mail;
			to.append(">");
		}
	}
	else
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENTS);

	if (CCRecipients.size())
	{
		for (i = 0; i < CCRecipients.size(); i++)
		{
			if (i > 0)
				cc. append(", ");

			cc += CCRecipients[i].Name;
			cc.append("<");
			cc += CCRecipients[i].Mail;
			cc.append(">");
		}
	}

	snprintf(header, BUFFER_SIZE, "Date: %d %s %d %d:%d:%d\r\n", timeinfo->tm_mday, month[timeinfo->tm_mon], timeinfo->tm_year + 1900, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec); 

	if (!m_sMailFrom.size())
		throw ECSmtp(ECSmtp::UNDEF_MAIL_FROM);

	strcat(header, "From: ");

	if (m_sNameFrom.size())
		strcat(header, m_sNameFrom.c_str());

	strcat(header, " <");
	strcat(header,m_sMailFrom.c_str());
	strcat(header, ">\r\n");

	if (m_sXMailer.size())
	{
		strcat(header, "X-Mailer: ");
		strcat(header, m_sXMailer.c_str());
		strcat(header, "\r\n");
	}

	if (m_sReplyTo.size())
	{
		strcat(header, "Reply-To: ");
		strcat(header, m_sReplyTo.c_str());
		strcat(header, "\r\n");
	}

	if (m_bReadReceipt)
	{
		strcat(header, "Disposition-Notification-To: ");

		if (m_sReplyTo.size())
			strcat(header, m_sReplyTo.c_str());
		else
			strcat(header, m_sNameFrom.c_str());

		strcat(header, "\r\n");
	}

	switch (m_iXPriority)
	{
		case XPRIORITY_HIGH:
		{
			strcat(header, "X-Priority: 2 (High)\r\n");
			break;
		}

		case XPRIORITY_NORMAL:
		{
			strcat(header, "X-Priority: 3 (Normal)\r\n");
			break;
		}

		case XPRIORITY_LOW:
		{
			strcat(header, "X-Priority: 4 (Low)\r\n");
			break;
		}

		default:
		{
			strcat(header, "X-Priority: 3 (Normal)\r\n");
			break;
		}
	}

	strcat(header, "To: ");
	strcat(header, to.c_str());
	strcat(header, "\r\n");

	if (CCRecipients.size())
	{
		strcat(header, "Cc: ");
		strcat(header, cc.c_str());
		strcat(header, "\r\n");
	}

	if (BCCRecipients.size())
	{
		strcat(header, "Bcc: ");
		strcat(header, bcc.c_str());
		strcat(header, "\r\n");
	}

	if (!m_sSubject.size()) 
	{
		strcat(header, "Subject:  ");
	}
	else
	{
		strcat(header, "Subject: ");
		strcat(header, m_sSubject.c_str());
	}

	strcat(header, "\r\n");

	strcat(header, "MIME-Version: 1.0\r\n");

	if (!Attachments.size())
	{
		if (m_bHTML)
			strcat(header, "Content-Type: text/html; charset=\"");
		else
			strcat(header, "Content-type: text/plain; charset=\"");

		strcat(header, m_sCharSet.c_str());
		strcat(header, "\"\r\n");
		strcat(header, "Content-Transfer-Encoding: 7bit\r\n");
		strcat(SendBuf, "\r\n");
	}
	else
	{
		strcat(header, "Content-Type: multipart/mixed; boundary=\"");
		strcat(header,BOUNDARY_TEXT);
		strcat(header, "\"\r\n");
		strcat(header, "\r\n");
		strcat(SendBuf, "--");
		strcat(SendBuf,BOUNDARY_TEXT);
		strcat(SendBuf, "\r\n");

		if (m_bHTML)
			strcat(SendBuf, "Content-type: text/html; charset=");
		else
			strcat(SendBuf, "Content-type: text/plain; charset=");

		strcat(header, m_sCharSet.c_str());
		strcat(header, "\r\n");
		strcat(SendBuf, "Content-Transfer-Encoding: 7bit\r\n");
		strcat(SendBuf, "\r\n");
	}
}

void CSmtp::ReceiveData(Command_Entry *pEntry)
{
	if (m_ssl != NULL)
	{
		ReceiveData_SSL(m_ssl, pEntry);
		return;
	}

	int res = 0;
	fd_set fdread;
	timeval time;

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	assert(RecvBuf);

	if (RecvBuf == NULL)
		throw ECSmtp(ECSmtp::RECVBUF_IS_EMPTY);

	FD_ZERO(&fdread);
	FD_SET(hSocket, &fdread);

	if ((res = select(hSocket + 1, &fdread, NULL, NULL, &time)) == SOCKET_ERROR)
	{
		FD_CLR(hSocket, &fdread);
		throw ECSmtp(ECSmtp::WSA_SELECT);
	}

	if (!res)
	{
		FD_CLR(hSocket, &fdread);
		throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
	}

	if (FD_ISSET(hSocket, &fdread))
	{
		res = recv(hSocket, RecvBuf, BUFFER_SIZE, 0);

		if (res == SOCKET_ERROR)
		{
			FD_CLR(hSocket, &fdread);
			throw ECSmtp(ECSmtp::WSA_RECV);
		}
	}

	FD_CLR(hSocket, &fdread);
	RecvBuf[res] = 0;

	if (res == 0)
		throw ECSmtp(ECSmtp::CONNECTION_CLOSED);
}

void CSmtp::SendData(Command_Entry *pEntry)
{
	if (m_ssl != NULL)
	{
		SendData_SSL(m_ssl, pEntry);
		return;
	}

	int idx = 0, res, nLeft = strlen(SendBuf);
	fd_set fdwrite;
	timeval time;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	assert(SendBuf);

	if (SendBuf == NULL)
		throw ECSmtp(ECSmtp::SENDBUF_IS_EMPTY);

	while (nLeft > 0)
	{
		FD_ZERO(&fdwrite);
		FD_SET(hSocket, &fdwrite);

		if ((res = select(hSocket + 1, NULL, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_CLR(hSocket, &fdwrite);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if (!res)
		{
			FD_CLR(hSocket, &fdwrite);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if (res && FD_ISSET(hSocket, &fdwrite))
		{
			res = send(hSocket, &SendBuf[idx], nLeft, 0);

			if (res == SOCKET_ERROR || res == 0)
			{
				FD_CLR(hSocket, &fdwrite);
				throw ECSmtp(ECSmtp::WSA_SEND);
			}

			nLeft -= res;
			idx += res;
		}
	}

	OutputDebugStringA(SendBuf);
	FD_CLR(hSocket, &fdwrite);
}

const char *CSmtp::GetLocalHostName(void)
{
	return m_sLocalHostName.c_str();
}

unsigned int CSmtp::GetRecipientCount(void) const
{
	return Recipients.size();
}

unsigned int CSmtp::GetBCCRecipientCount(void) const
{
	return BCCRecipients.size();
}

unsigned int CSmtp::GetCCRecipientCount(void) const
{
	return CCRecipients.size();
}

const char *CSmtp::GetReplyTo(void) const
{
	return m_sReplyTo.c_str();
}

const char *CSmtp::GetMailFrom(void) const
{
	return m_sMailFrom.c_str();
}

const char *CSmtp::GetSenderName(void) const
{
	return m_sNameFrom.c_str();
}

const char *CSmtp::GetSubject(void) const
{
	return m_sSubject.c_str();
}

const char *CSmtp::GetXMailer(void) const
{
	return m_sXMailer.c_str();
}

CSmptXPriority CSmtp::GetXPriority(void) const
{
	return m_iXPriority;
}

const char *CSmtp::GetMsgLineText(unsigned int Line) const
{
	if (Line >= MsgBody.size())
		throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);

	return MsgBody.at(Line).c_str();
}

unsigned int CSmtp::GetMsgLines(void) const
{
	return MsgBody.size();
}

void CSmtp::SetCharSet(const char *sCharSet)
{
	m_sCharSet = sCharSet;
}

void CSmtp::SetLocalHostName(const char *sLocalHostName)
{
	m_sLocalHostName = sLocalHostName;
}

void CSmtp::SetXPriority(CSmptXPriority priority)
{
	m_iXPriority = priority;
}

void CSmtp::SetReplyTo(const char *ReplyTo)
{
	m_sReplyTo = ReplyTo;
}

void CSmtp::SetReadReceipt(bool requestReceipt)
{
	m_bReadReceipt = requestReceipt;
}

void CSmtp::SetSenderMail(const char *EMail)
{
	m_sMailFrom = EMail;
}

void CSmtp::SetSenderName(const char *Name)
{
	m_sNameFrom = Name;
}

void CSmtp::SetSubject(const char *Subject)
{
	m_sSubject = Subject;
}

void CSmtp::SetXMailer(const char *XMailer)
{
	m_sXMailer = XMailer;
}

void CSmtp::SetLogin(const char *Login)
{
	m_sLogin = Login;
}

void CSmtp::SetPassword(const char *Password)
{
	m_sPassword = Password;
}

void CSmtp::SetSMTPServer(const char *SrvName, const unsigned short SrvPort, bool authenticate)
{
	m_iSMTPSrvPort = SrvPort;
	m_sSMTPSrvName = SrvName;
	m_bAuthenticate = authenticate;
}

std::string ECSmtp::GetErrorText(void) const
{
	switch (ErrorCode)
	{
		case ECSmtp::CSMTP_NO_ERROR: return "";
		case ECSmtp::WSA_STARTUP: return "Unable to initialise winsock2";
		case ECSmtp::WSA_VER: return "Wrong version of the winsock2";
		case ECSmtp::WSA_SEND: return "Function send() failed";
		case ECSmtp::WSA_RECV: return "Function recv() failed";
		case ECSmtp::WSA_CONNECT: return "Function connect failed";
		case ECSmtp::WSA_GETHOSTBY_NAME_ADDR: return "Unable to determine remote server";
		case ECSmtp::WSA_INVALID_SOCKET: return "Invalid winsock2 socket";
		case ECSmtp::WSA_HOSTNAME: return "Function hostname() failed";
		case ECSmtp::WSA_IOCTLSOCKET: return "Function ioctlsocket() failed";
		case ECSmtp::BAD_IPV4_ADDR: return "Improper IPv4 address";
		case ECSmtp::UNDEF_MSG_HEADER: return "Undefined message header";
		case ECSmtp::UNDEF_MAIL_FROM: return "Undefined mail sender";
		case ECSmtp::UNDEF_SUBJECT: return "Undefined message subject";
		case ECSmtp::UNDEF_RECIPIENTS: return "Undefined at least one reciepent";
		case ECSmtp::UNDEF_RECIPIENT_MAIL: return "Undefined recipent mail";
		case ECSmtp::UNDEF_LOGIN: return "Undefined user login";
		case ECSmtp::UNDEF_PASSWORD: return "Undefined user password";
		case ECSmtp::BAD_LOGIN_PASSWORD: return "Invalid user login or password";
		case ECSmtp::BAD_DIGEST_RESPONSE: return "Server returned a bad digest MD5 response";
		case ECSmtp::BAD_SERVER_NAME: return "Unable to determine server name for digest MD5 response";
		case ECSmtp::COMMAND_MAIL_FROM: return "Server returned error after sending MAIL FROM";
		case ECSmtp::COMMAND_EHLO: return "Server returned error after sending EHLO";
		case ECSmtp::COMMAND_AUTH_PLAIN: return "Server returned error after sending AUTH PLAIN";
		case ECSmtp::COMMAND_AUTH_LOGIN: return "Server returned error after sending AUTH LOGIN";
		case ECSmtp::COMMAND_AUTH_CRAMMD5: return "Server returned error after sending AUTH CRAM-MD5";
		case ECSmtp::COMMAND_AUTH_DIGESTMD5: return "Server returned error after sending AUTH DIGEST-MD5";
		case ECSmtp::COMMAND_DIGESTMD5: return "Server returned error after sending MD5 DIGEST";
		case ECSmtp::COMMAND_DATA: return "Server returned error after sending DATA";
		case ECSmtp::COMMAND_QUIT: return "Server returned error after sending QUIT";
		case ECSmtp::COMMAND_RCPT_TO: return "Server returned error after sending RCPT TO";
		case ECSmtp::MSG_BODY_ERROR: return "Error in message body";
		case ECSmtp::CONNECTION_CLOSED: return "Server has closed the connection";
		case ECSmtp::SERVER_NOT_READY: return "Server is not ready";
		case ECSmtp::SERVER_NOT_RESPONDING: return "Server not responding";
		case ECSmtp::FILE_NOT_EXIST: return "Attachment file does not exist";
		case ECSmtp::MSG_TOO_BIG: return "Message is too big";
		case ECSmtp::BAD_LOGIN_PASS: return "Bad login or password";
		case ECSmtp::UNDEF_XYZ_RESPONSE: return "Undefined xyz SMTP response";
		case ECSmtp::LACK_OF_MEMORY: return "Lack of memory";
		case ECSmtp::TIME_ERROR: return "time() error";
		case ECSmtp::RECVBUF_IS_EMPTY: return "RecvBuf is empty";
		case ECSmtp::SENDBUF_IS_EMPTY: return "SendBuf is empty";
		case ECSmtp::OUT_OF_MSG_RANGE: return "Specified line number is out of message size";
		case ECSmtp::COMMAND_EHLO_STARTTLS: return "Server returned error after sending STARTTLS";
		case ECSmtp::SSL_PROBLEM: return "SSL problem";
		case ECSmtp::COMMAND_DATABLOCK: return "Failed to send data block";
		case ECSmtp::STARTTLS_NOT_SUPPORTED: return "The STARTTLS command is not supported by the server";
		case ECSmtp::LOGIN_NOT_SUPPORTED: return "AUTH LOGIN is not supported by the server";
	}

	return "Undefined error id";
}

void CSmtp::SayHello(void)
{
	Command_Entry *pEntry = FindCommandEntry(command_EHLO);
	snprintf(SendBuf, BUFFER_SIZE, "EHLO %s\r\n", GetLocalHostName() != NULL ? m_sLocalHostName.c_str() : "domain");
	SendData(pEntry);
	ReceiveResponse(pEntry);
	m_bConnected=true;
}

void CSmtp::SayQuit(void)
{
	Command_Entry *pEntry = FindCommandEntry(command_QUIT);
	snprintf(SendBuf, BUFFER_SIZE, "QUIT\r\n");
	m_bConnected = false;
	SendData(pEntry);
	ReceiveResponse(pEntry);
}

void CSmtp::StartTls(void)
{
	if (IsKeywordSupported(RecvBuf, "STARTTLS") == false)
		throw ECSmtp(ECSmtp::STARTTLS_NOT_SUPPORTED);

	Command_Entry *pEntry = FindCommandEntry(command_STARTTLS);
	snprintf(SendBuf, BUFFER_SIZE, "STARTTLS\r\n");
	SendData(pEntry);
	ReceiveResponse(pEntry);

	OpenSSLConnect();
}

void CSmtp::ReceiveData_SSL(SSL *ssl, Command_Entry *pEntry)
{
	int res = 0;
	int offset = 0;
	fd_set fdread;
	fd_set fdwrite;
	timeval time;

	int read_blocked_on_write = 0;

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	assert(RecvBuf);

	if (RecvBuf == NULL)
		throw ECSmtp(ECSmtp::RECVBUF_IS_EMPTY);

	bool bFinish = false;

	while (!bFinish)
	{
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		FD_SET(hSocket, &fdread);

		if (read_blocked_on_write)
		{
			FD_SET(hSocket, &fdwrite);
		}

		if ((res = select(hSocket + 1, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if (!res)
		{
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if (FD_ISSET(hSocket, &fdread) || (read_blocked_on_write && FD_ISSET(hSocket, &fdwrite)))
		{
			while (1)
			{
				read_blocked_on_write = 0;

				const int buff_len = 1024;
				char buff[buff_len];

				res = SSL_read(ssl, buff, buff_len);

				int ssl_err = SSL_get_error(ssl, res);

				if (ssl_err == SSL_ERROR_NONE)
				{
					if (offset + res > BUFFER_SIZE - 1)
					{
						FD_ZERO(&fdread);
						FD_ZERO(&fdwrite);
						throw ECSmtp(ECSmtp::LACK_OF_MEMORY);
					}

					memcpy(RecvBuf + offset, buff, res);
					offset += res;

					if (SSL_pending(ssl))
					{
						continue;
					}
					else
					{
						bFinish = true;
						break;
					}
				}
				else if (ssl_err == SSL_ERROR_ZERO_RETURN)
				{
					bFinish = true;
					break;
				}
				else if (ssl_err == SSL_ERROR_WANT_READ)
				{
					break;
				}
				else if (ssl_err == SSL_ERROR_WANT_WRITE)
				{
					read_blocked_on_write = 1;
					break;
				}
				else
				{
					FD_ZERO(&fdread);
					FD_ZERO(&fdwrite);
					throw ECSmtp(ECSmtp::SSL_PROBLEM);
				}
			}
		}
	}

	FD_ZERO(&fdread);
	FD_ZERO(&fdwrite);
	RecvBuf[offset] = 0;

	if (offset == 0)
		throw ECSmtp(ECSmtp::CONNECTION_CLOSED);
}

void CSmtp::ReceiveResponse(Command_Entry *pEntry)
{
	std::string line;
	int reply_code = 0;
	bool bFinish = false;

	while (!bFinish)
	{
		ReceiveData(pEntry);
		line.append(RecvBuf);
		size_t len = line.length();
		size_t begin = 0;
		size_t offset = 0;

		while (1)
		{
			while (offset + 1 < len)
			{
				if (line[offset] == '\r' && line[offset+1] == '\n')
					break;

				++offset;
			}

			if (offset + 1 < len)
			{
				offset += 2;

				if (offset - begin >= 5)
				{
					if (isdigit(line[begin]) && isdigit(line[begin + 1]) && isdigit(line[begin + 2]))
					{
						if (offset - begin == 5 || line[begin + 3] == ' ')
						{
							reply_code = (line[begin] - '0') * 100 + (line[begin + 1] - '0') * 10 + line[begin + 2] - '0';
							bFinish = true;
							break;
						}
					}
				}

				begin = offset;
			}
			else
			{
				break;
			}
		}
	}

	snprintf(RecvBuf, BUFFER_SIZE, line.c_str());
	OutputDebugStringA(RecvBuf);

	if (reply_code != pEntry->valid_reply_code)
		throw ECSmtp(pEntry->error);
}

void CSmtp::SendData_SSL(SSL *ssl, Command_Entry *pEntry)
{
	int offset = 0, res, nLeft = strlen(SendBuf);
	fd_set fdwrite;
	fd_set fdread;
	timeval time;

	int write_blocked_on_read = 0;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	assert(SendBuf);

	if (SendBuf == NULL)
		throw ECSmtp(ECSmtp::SENDBUF_IS_EMPTY);

	while (nLeft > 0)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		FD_SET(hSocket, &fdwrite);

		if (write_blocked_on_read)
		{
			FD_SET(hSocket, &fdread);
		}

		if ((res = select(hSocket + 1, &fdread, &fdwrite,NULL, &time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if (!res)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if (FD_ISSET(hSocket, &fdwrite) || (write_blocked_on_read && FD_ISSET(hSocket, &fdread)))
		{
			write_blocked_on_read = 0;

			res = SSL_write(ssl, SendBuf+offset, nLeft);

			switch (SSL_get_error(ssl,res))
			{
				case SSL_ERROR_NONE:
				{
					nLeft -= res;
					offset += res;
					break;
				}

				case SSL_ERROR_WANT_WRITE:
				{
					break;
				}

				case SSL_ERROR_WANT_READ:
				{
					write_blocked_on_read = 1;
					break;
				}

				default:
				{
					FD_ZERO(&fdread);
					FD_ZERO(&fdwrite);
					throw ECSmtp(ECSmtp::SSL_PROBLEM);
				}
			}

		}
	}

	OutputDebugStringA(SendBuf);
	FD_ZERO(&fdwrite);
	FD_ZERO(&fdread);
}

void CSmtp::InitOpenSSL(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	m_ctx = SSL_CTX_new(SSLv23_client_method());

	if (m_ctx == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);
}

void CSmtp::OpenSSLConnect(void)
{
	if (m_ctx == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);

	m_ssl = SSL_new(m_ctx); 

	if (m_ssl == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);

	SSL_set_fd (m_ssl, (int)hSocket);
	SSL_set_mode(m_ssl, SSL_MODE_AUTO_RETRY);

	int res = 0;
	fd_set fdwrite;
	fd_set fdread;
	int write_blocked = 0;
	int read_blocked = 0;

	timeval time;
	time.tv_sec = TIME_IN_SEC;
	time.tv_usec = 0;

	while (1)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		if (write_blocked)
			FD_SET(hSocket, &fdwrite);

		if (read_blocked)
			FD_SET(hSocket, &fdread);

		if (write_blocked || read_blocked)
		{
			write_blocked = 0;
			read_blocked = 0;

			if ((res = select(hSocket + 1, &fdread, &fdwrite,NULL, &time)) == SOCKET_ERROR)
			{
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}

			if (!res)
			{
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
			}
		}

		res = SSL_connect(m_ssl);

		switch (SSL_get_error(m_ssl, res))
		{
			case SSL_ERROR_NONE:
			{
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				return;
				break;
			}

			case SSL_ERROR_WANT_WRITE:
			{
				write_blocked = 1;
				break;
			}

			case SSL_ERROR_WANT_READ:
			{
				read_blocked = 1;
				break;
			}

			default:
			{
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECSmtp(ECSmtp::SSL_PROBLEM);
			}
		}
	}
}

void CSmtp::CleanupOpenSSL(void)
{
	if (m_ssl != NULL)
	{
		SSL_shutdown(m_ssl);
		SSL_free (m_ssl);
		m_ssl = NULL;
	}

	if (m_ctx != NULL)
	{
		SSL_CTX_free(m_ctx);
		m_ctx = NULL;
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	}
}