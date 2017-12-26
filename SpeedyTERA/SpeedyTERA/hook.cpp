#include "dllmain.h"
#include "hook.h"

bool bDataCompare(const BYTE *pData, const BYTE *bMask, const char *szMask) {
  for (; *szMask; ++szMask, ++pData, ++bMask)
    if (*szMask == 'x' && *pData != *bMask)
      return false;
  return (*szMask) == NULL;
}

DWORD dwFindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char *szMask) {
  for (DWORD i = 0; i < dwLen; i++)
    if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
      return (DWORD)(dwAddress + i);
  return 0;
}

DWORD absAddr(DWORD rel1, DWORD rel2) {
  DWORD tmp1 = *((DWORD *)(rel1 + 1));
  DWORD tmp2 = rel1 + tmp1 + 5;
  DWORD tmp3 = tmp2 - rel2 - 5;
  return tmp3;
}
