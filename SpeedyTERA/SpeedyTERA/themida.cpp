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

//themida monitor
BYTE *sigData2 = (BYTE *)"\x81\xEB\xE1\x30\xCB\x3F\x02\x03"; 
char *sigMask2 = "xxxxxxxx";

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

void patchThemida(void *base, size_t size) {
  //backup original memory
  fakeTera = malloc(size);
  memcpy(fakeTera, base, size);
  fakeOffset = (DWORD)fakeTera - (DWORD)base;

  //themida patch monitor of memory monitor
  DWORD patch1Tmp = dwFindPattern((DWORD)base, size, sigData1, sigMask1);
  patch1Retn = patch1Tmp + 13;

  *((BYTE *)(patch1Tmp)) = 0xE9;
  *((DWORD *)(patch1Tmp + 1)) = absAddr((DWORD)&themidaPatch1, patch1Tmp);

  //themida patch memory monitor
  DWORD patch2Tmp = dwFindPattern((DWORD)base, size, sigData2, sigMask2);
  patch2Retn = patch2Tmp + 6;

  *((BYTE *)(patch2Tmp)) = 0xE9;
  *((DWORD *)(patch2Tmp + 1)) = absAddr((DWORD)&themidaPatch2, patch2Tmp);
  *((BYTE *)(patch2Tmp + 5)) = 0x90;
}
