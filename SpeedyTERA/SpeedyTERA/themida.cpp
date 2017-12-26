#include "dllmain.h"
#include "themida.h"

#include "hook.h"

LPVOID fakeTera;
DWORD fakeOffset;
DWORD patch1Retn;
DWORD patch2Retn;

//themida monitor of the monitor
BYTE *sigData1 = (BYTE *)"\xBB\x00\x00\x00\x00\x81\xF7\x28\x00\x00\x00\x8B\x36\x8B\x36\xBF\x00\x04\x00\x00"; 
char *sigMask1 = "xxxxxxxxxxxxxxxxxxxx";
int sigReturn1 = 13;

//themida monitor
BYTE *sigData2 = (BYTE *)"\x81\xEB\xE1\x30\xCB\x3F\x02\x03"; 
char *sigMask2 = "xxxxxxxx";
int sigReturn2 = 6;

void __declspec(naked) themidaPatch1() {
  __asm {
    xor ebx, ebx
    xor edi, 0x28
    mov esi, [esi]
    add esi, fakeOffset
    jmp patch1Retn
  }
}

void __declspec(naked) themidaPatch2() {
  __asm {
    sub ebx, 0x3FCB30E1
    add ebx, fakeOffset
    jmp patch2Retn
  }
}

DWORD patch1Tmp, patch2Tmp;
void patchThemida() {
  //backup original memory
  fakeTera = malloc(teraSize);
  memcpy(fakeTera, teraBase, teraSize);
  fakeOffset = (DWORD)fakeTera - (DWORD)teraBase;

  //themida patch monitor of memory monitor
  patch1Tmp = dwFindPattern((DWORD)teraBase, teraSize, sigData1, sigMask1);
  patch1Retn = patch1Tmp + sigReturn1;

  *((BYTE *)(patch1Tmp)) = 0xE9;
  *((DWORD *)(patch1Tmp + 1)) = absAddr((DWORD)&themidaPatch1, patch1Tmp);

  //themida patch memory monitor
  patch2Tmp = dwFindPattern((DWORD)teraBase, teraSize, sigData2, sigMask2);
  patch2Retn = patch2Tmp + sigReturn2;

  *((BYTE *)(patch2Tmp)) = 0xE9;
  *((DWORD *)(patch2Tmp + 1)) = absAddr((DWORD)&themidaPatch2, patch2Tmp);
  *((BYTE *)(patch2Tmp + 5)) = 0x90;
}

void restoreThemida() {
  memcpy((LPVOID)patch1Tmp, (LPVOID)(patch1Tmp + fakeOffset), sigReturn1);
  memcpy((LPVOID)patch2Tmp, (LPVOID)(patch2Tmp + fakeOffset), sigReturn2);
  free(fakeTera);
}
