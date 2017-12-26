#pragma once
bool bDataCompare(const BYTE *pData, const BYTE *bMask, const char *szMask);
DWORD dwFindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char *szMask);
DWORD absAddr(DWORD rel1, DWORD rel2);
