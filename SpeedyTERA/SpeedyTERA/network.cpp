#include "dllmain.h"
#include "network.h"

#include "hook.h"

//enc/dec functions (2 with same pattern)
BYTE *sigCryptoData = (BYTE *)"\x55\x8B\xEC\x83\xEC\x28\x8B\x41\x04\x8B\x55\x0C\x53\x56\x57"; 
char *sigCryptoMask = "xxxxxxxxxxxxxxx";

//decrypt calls
BYTE *sigDecData1 = (BYTE *)"\x5D\xC2\x08\x00\xFF\x75\x0C\x8D\x8E\x68\x01\x00\x00\xFF\x75\x08\xE8\xCC\xCC\xCC\xCC\xB0\x01\x5E";
char *sigDecMask1 = "xxxxxxxxxxxxxxxxx????xxx";
int sigDecOffset1 = 16;
BYTE *sigDecData2 = (BYTE *)"\x68\x80\x00\x00\x00\x53\x8D\x89\x0C\x01\x00\x00\xE8\xCC\xCC\xCC\xCC\x8B\x95\x78\xFF\xFF\xFF\xB9";
char *sigDecMask2 = "xxxxxxxxxxxxx????xxxxxxx";
int sigDecOffset2 = 12;

//encrypt calls
BYTE *sigEncData1 = (BYTE *)"\x8D\x88\x68\x01\x00\x00\xE8\xCC\xCC\xCC\xCC\x8B\x85\x78\xFF\xFF\xFF\xB9\x29\x00\x00\x00\x33\xD2";
char *sigEncMask1 = "xxxxxxx????xxxxxxxxxxxxx";
int sigEncOffset1 = 6;
BYTE *sigEncData2 = (BYTE *)"\xFF\x75\x0C\x8D\x8E\x0C\x01\x00\x00\xFF\x75\x08\xE8\xCC\xCC\xCC\xCC\xB0\x01\x5E\x5D\xC2\x08\x00";
char *sigEncMask2 = "xxxxxxxxxxxxx????xxxxxxx";
int sigEncOffset2 = 12;

std::vector<defHookCallback> cbOnBeforeEncrypt = {};
std::vector<defHookCallback> cbOnAfterEncrypt = {};
std::vector<defHookCallback> cbOnBeforeDecrypt = {};
std::vector<defHookCallback> cbOnAfterDecrypt = {};

char * encBuffer;
size_t encSize;
void onBeforeEncrypt() {
  for (defHookCallback callback : cbOnBeforeEncrypt) {
    callback(encBuffer, encSize);
  }
}
void onAfterEncrypt() {
  for (defHookCallback callback : cbOnAfterEncrypt) {
    callback(encBuffer, encSize);
  }
}

char * decBuffer;
size_t decSize;
void onBeforeDecrypt() {
  for (defHookCallback callback : cbOnBeforeDecrypt) {
    callback(decBuffer, decSize);
  }
}
void onAfterDecrypt() {
  for (defHookCallback callback : cbOnAfterDecrypt) {
    callback(decBuffer, decSize);
  }
}

DWORD retnEncAddr, realEncrypt;
void __declspec(naked) encryptHook() {
  __asm {
    push eax
    mov eax, dword ptr ss : [esp + 0x08]
    mov encBuffer, eax
    mov eax, dword ptr ss : [esp + 0x0C]
    mov [encSize], eax
    mov eax, dword ptr ss : [esp + 0x04]
    mov [retnEncAddr], eax
    pop eax

    pushad
    call onBeforeEncrypt
    popad

    add esp, 4
    call[realEncrypt]

    pushad
    call onAfterEncrypt
    popad

    push retnEncAddr
    retn
  }
}

DWORD retnDecAddr, realDecrypt;
void __declspec(naked) decryptHook() {
  __asm {
    push eax
    mov eax, dword ptr ss : [esp + 0x08]
    mov decBuffer, eax
    mov eax, dword ptr ss : [esp + 0x0C]
    mov [decSize], eax
    mov eax, dword ptr ss : [esp + 0x04]
    mov [retnDecAddr], eax
    pop eax

    pushad
    call onBeforeDecrypt
    popad

    add esp, 4
    call [realDecrypt]

    pushad
    call onAfterDecrypt
    popad

    push retnDecAddr
    retn
  }
}

void patchCrypto(void *base, size_t size) {
  //get crypto functions addresses
  realEncrypt = dwFindPattern((DWORD)base, size, sigCryptoData, sigCryptoMask);

  DWORD searchAddr = realEncrypt + sizeof(sigCryptoData);
  SIZE_T searchSize = size - (searchAddr - (DWORD)base);
  realDecrypt = dwFindPattern(searchAddr, searchSize, sigCryptoData, sigCryptoMask);

  //patch encrypt calls
  DWORD encPatch1 = dwFindPattern((DWORD)base, size, sigEncData1, sigEncMask1);
  encPatch1 += sigEncOffset1;
  *((DWORD *)(encPatch1 + 1)) = absAddr((DWORD)&encryptHook, encPatch1);

  DWORD encPatch2 = dwFindPattern((DWORD)base, size, sigEncData2, sigEncMask2);
  encPatch2 += sigEncOffset2;
  *((DWORD *)(encPatch2 + 1)) = absAddr((DWORD)&encryptHook, encPatch2);

  //patch decrypt calls
  DWORD decPatch1 = dwFindPattern((DWORD)base, size, sigDecData1, sigDecMask1);
  decPatch1 += sigDecOffset1;
  *((DWORD *)(decPatch1 + 1)) = absAddr((DWORD)&decryptHook, decPatch1);

  DWORD decPatch2 = dwFindPattern((DWORD)base, size, sigDecData2, sigDecMask2);
  decPatch2 += sigDecOffset2;
  *((DWORD *)(decPatch2 + 1)) = absAddr((DWORD)&decryptHook, decPatch2);

  //debug
  printf("[Debug] encrypt function: 0x%04X\n", realEncrypt);
  printf("[Debug] encrypt call1: 0x%04X\n", encPatch1);
  printf("[Debug] encrypt call2: 0x%04X\n", encPatch2);

  printf("[Debug] decrypt function: 0x%04X\n", realDecrypt);
  printf("[Debug] decrypt call1: 0x%04X\n", decPatch1);
  printf("[Debug] decrypt call2: 0x%04X\n", decPatch2);

}
