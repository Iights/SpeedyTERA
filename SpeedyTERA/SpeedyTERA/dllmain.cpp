#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>

#include "dllmain.h"

char *TERA_EXE = "TERA.exe";
extern "C" __declspec (dllexport) void __cdecl dummy(HWND hWnd, HINSTANCE hInst, LPTSTR lpCmdLine, int nCmdShow) { }

DWORD getPID(char *szName) {
  DWORD pID = 0;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  PROCESSENTRY32 pe = { sizeof(pe) };
  if (Process32First(hSnapshot, &pe)) {
    do {
      if (_stricmp(pe.szExeFile, szName) == 0) {
        pID = pe.th32ProcessID;
        break;
      }
    } while (Process32Next(hSnapshot, &pe));
  }

  CloseHandle(hSnapshot);
  return pID;
}

BOOL getModule(DWORD dwPID, char *szName, MODULEENTRY32 &module) {
  BOOL ret = false;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

  MODULEENTRY32 me = { sizeof(me) };
  if (Module32First(hSnapshot, &me)) {
    do {
      if (_stricmp(me.szModule, szName) == 0) {
        ret = true;
        module = me;
        break;
      }
    } while (Module32Next(hSnapshot, &me));
  }

  CloseHandle(hSnapshot);
  return ret;
}

BOOL injectDLL(char *szDLL) {
  DWORD pID = getPID(TERA_EXE);
  if (pID == 0) return FALSE;

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
  if (hProcess == NULL)  return FALSE;

  SIZE_T len = strlen(szDLL);
  LPVOID pName = VirtualAllocEx(hProcess, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (pName == NULL) return FALSE;

  BOOL bStatus = WriteProcessMemory(hProcess, pName, szDLL, len, nullptr);
  if (bStatus == 0) return FALSE;

  HMODULE hKernel = GetModuleHandle("kernel32.dll");
  FARPROC pLoadLibrary = GetProcAddress(hKernel, "LoadLibraryA");
  if (pLoadLibrary == NULL) return FALSE;

  HANDLE hThreadId = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), pName, NULL, nullptr);
  if (hThreadId == NULL) return FALSE;

  WaitForSingleObject(hThreadId, INFINITE);

  VirtualFreeEx(hProcess, pName, len, MEM_RELEASE);
  CloseHandle(hProcess);

  return TRUE;
}

char buf[4096] = { 0 };
char hexBuf[50] = { 0 };
DWORD returnAddress;
__declspec(naked) void encryptHook(char* buffer, size_t size) {
  __asm {
    push ebp
    mov ebp, esp
    sub esp, 0x28
  }
  __asm pushad

  for (size_t i = 0; i < size; i++) {
    sprintf_s(hexBuf, "%02X", (unsigned char)buffer[i]);
    strcat_s(buf, hexBuf);
  }
  MessageBox(0, buf, "ENCRYPT", 0);

  __asm popad
  __asm jmp returnAddress
}

void initHooked(HMODULE hDLL) {
  DWORD pID = getPID(TERA_EXE);

  MODULEENTRY32 me;
  getModule(pID, TERA_EXE, me);
  DWORD TeraBase = (DWORD)me.modBaseAddr;

  returnAddress = (TeraBase + ADDR_ENCRYPT_FN1 + 5);

  DWORD lpEncryptJmp = (DWORD)&encryptHook;
  DWORD lpEncryptRel = *((DWORD *)(lpEncryptJmp + 1));
  DWORD lpEncryptAbs = lpEncryptJmp + lpEncryptRel + 5 - returnAddress;

  *((BYTE *)(TeraBase + ADDR_ENCRYPT_FN1)) = 0xE9; //JMP
  *((DWORD *)(TeraBase + ADDR_ENCRYPT_FN1 + 1)) = lpEncryptAbs;
  *((BYTE *)returnAddress) = 0x90; //NOP

  MessageBox(0, "HOOKED TERA.EXE", 0, 0);

}

void initAlone(HMODULE hDLL) {
  char szDLL[MAX_PATH];
  GetModuleFileName(hDLL, szDLL, MAX_PATH);

  if (injectDLL(szDLL) == FALSE) {
    MessageBox(0, "[!] TERA.exe not running or not enough privileges", "SpeedyTera ERROR", MB_ICONERROR | MB_OK);
  }

}

int __stdcall DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
  switch (ulReason) {
  case DLL_PROCESS_ATTACH: {
    char szPath[MAX_PATH];
    GetModuleFileName(GetModuleHandle(0), szPath, MAX_PATH);
    char *szApp = strrchr(szPath, '\\') + 1;
    //MessageBoxA(0, szApp, "DllMain", 0);

    if (_stricmp(szApp, TERA_EXE) == 0) {
      initHooked(hModule);
    }
    else {
      initAlone(hModule);
    }

    break;
  }
  case DLL_PROCESS_DETACH:
    break;
  }
  return 1;
}
