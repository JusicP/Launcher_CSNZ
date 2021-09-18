#include <interface.h>
#include "ICommandLine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const int MAX_PARAMETER_LEN = 128;

class CCommandLine : public ICommandLine
{
public:
	CCommandLine(void);
	~CCommandLine(void);

public:
	void CreateCmdLine(const char *commandline);
	const char *GetCmdLine(void) const;
	const char *CheckParm(const char *psz, const char **ppszValue = 0) const;
	void RemoveParm(const char *parm);
	void AppendParm(const char *pszParm, const char *pszValues);
	void SetParm(const char *pszParm, const char *pszValues);
	void SetParm(const char *pszParm, int iValue);

private:
	enum
	{
		MAX_PARAMETER_LEN = 128,
		MAX_PARAMETERS = 256,
	};

	void LoadParametersFromFile(char *&pSrc, char *&pDst);

private:
	char *m_pszCmdLine;
};

CCommandLine g_CmdLine;
ICommandLine *g_pCmdLine = (ICommandLine *)&g_CmdLine;

ICommandLine *CommandLine(void)
{
	return g_pCmdLine;
}

CCommandLine::CCommandLine(void)
{
	m_pszCmdLine = 0;
}

CCommandLine::~CCommandLine(void)
{
	delete [] m_pszCmdLine;
}

void CCommandLine::LoadParametersFromFile(char *&pSrc, char *&pDst)
{
	char szFileName[_MAX_PATH];
	char *pOut;

	pSrc++;
	pOut = szFileName;

	while (*pSrc && *pSrc != ' ')
		*pOut++ = *pSrc++;

	*pOut = '\0';

	if (*pSrc)
		pSrc++;

	FILE *fp = fopen(szFileName, "r");

	if (fp)
	{
		char c;
		c = (char)fgetc(fp);

		while (c != EOF)
		{
			if (c == '\n')
				c = ' ';

			*pDst++ = c;
			c = (char)fgetc(fp);
		}

		*pDst++ = ' ';
		fclose(fp);
	}
	else
		printf("Parameter file '%s' not found, skipping...", szFileName);
}

void CCommandLine::SetParm(const char *pszParm, const char *pszValues)
{
	RemoveParm(pszParm);
	AppendParm(pszParm, pszValues);
}

const char *CCommandLine::GetCmdLine(void) const
{
	return m_pszCmdLine;
}

const char *CCommandLine::CheckParm(const char *psz, const char **ppszValue) const
{
	static char sz[MAX_PARAMETER_LEN];
	char *pret;

	if (!m_pszCmdLine)
		return NULL;

	pret = strstr(m_pszCmdLine, psz);

	if (pret && ppszValue)
	{
		char *p1 = pret;
		*ppszValue = 0;

		while (*p1 && (*p1 != 32))
			p1++;

		char *p2 = ++p1;
		int i;

		for (i = 0; i < MAX_PARAMETER_LEN; i++)
		{
			if (!*p2 || (*p2 == 32))
				break;

			sz[i] = *p2++;
		}

		sz[i] = 0;
		*ppszValue = &sz[0];
	}

	return pret;
}

void CCommandLine::SetParm(const char *pszParm, int iValue)
{
	char pszValue[64];
	_snprintf(pszValue, sizeof(pszValue), "%d", iValue);
	SetParm(pszParm, iValue);
}

void CCommandLine::AppendParm(const char *pszParm, const char *pszValues)
{
	int nNewLength = 0;
	char *pCmdString;

	nNewLength = strlen(pszParm);

	if (pszValues)
		nNewLength += strlen(pszValues) + 1;

	if (!m_pszCmdLine)
	{
		m_pszCmdLine = new char [nNewLength];
		strcpy(m_pszCmdLine, pszParm);

		if (pszValues)
		{
			strcat(m_pszCmdLine, " ");
			strcat(m_pszCmdLine, pszValues);
		}

		return;
	}

	RemoveParm(pszParm);

	nNewLength += strlen(m_pszCmdLine) + 1 + 1;
	pCmdString = new char [nNewLength];
	memset(pCmdString, 0, nNewLength);

	strcpy(pCmdString, m_pszCmdLine);
	strcat(pCmdString, " ");
	strcat(pCmdString, pszParm);

	if (pszValues)
	{
		strcat(pCmdString, " ");
		strcat(pCmdString, pszValues);
	}

	delete [] m_pszCmdLine;
	m_pszCmdLine = pCmdString;
}

void CCommandLine::RemoveParm(const char *pszParm)
{
	if (!m_pszCmdLine)
		return;

	if (!pszParm || !*pszParm)
		return;

	char *p, *found;
	char *pnextparam;
	int n;
	int curlen;
	int curpos;

	while (1)
	{
		p = m_pszCmdLine;
		curlen = strlen(p);
		found = strstr(p, pszParm);

		if (!found)
			break;

		curpos = found - p;
		pnextparam = found + 1;

		while (pnextparam && *pnextparam && (*pnextparam != '-') && (*pnextparam != '+'))
			pnextparam++;

		if (pnextparam && *pnextparam)
		{
			n = curlen - (pnextparam - p);

			if (found[0] == ' ')
			{
				memcpy(found + 1, pnextparam, n);
				found[n + 1] = '\0';
			}
			else
			{
				memcpy(found, pnextparam, n);
				found[n] = '\0';
			}
		}
		else
		{
			n = pnextparam - found;
			memset(found, 0, n);
		}
	}

	while (m_pszCmdLine[strlen(m_pszCmdLine) - 1] == ' ')
		m_pszCmdLine[strlen(m_pszCmdLine) - 1] = '\0';
}

void CCommandLine::CreateCmdLine(const char *commandline)
{
	if (m_pszCmdLine)
		delete [] m_pszCmdLine;

	char szFull[4096];
	int len = strlen(commandline) + 1;
	char *pOrig = new char [len];
	memcpy(pOrig, commandline, len);

	char *pSrc, *pDst;

	pDst = szFull;
	pSrc = pOrig;

	bool bContinue = true;

	while (*pSrc)
	{
		if (bContinue && *pSrc == '@')
		{
			LoadParametersFromFile(pSrc, pDst);
			continue;
		}

		bContinue = (isspace(*pSrc) != false);
		*pDst++ = *pSrc++;
	}

	*pDst = '\0';

	len = strlen(szFull) + 1;
	m_pszCmdLine = new char [len];
	memcpy(m_pszCmdLine, szFull, len);
}