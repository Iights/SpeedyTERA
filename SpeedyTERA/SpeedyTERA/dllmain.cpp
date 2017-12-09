#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <vector>

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

typedef int(__stdcall * defOnBeforeEncrypt)(char *, size_t);
std::vector<defOnBeforeEncrypt> cbOnBeforeEncrypt = {};

void onBeforeEncrypt(char* buffer, size_t size) {
  for (defOnBeforeEncrypt callback : cbOnBeforeEncrypt) {
    callback(buffer, size);
  }
}

DWORD returnAddress;
__declspec(naked) void encryptHook(char* buffer, size_t size) {
  __asm {
    push ebp
    mov ebp, esp
    sub esp, 0x28
  }
  __asm pushad

  onBeforeEncrypt(buffer, size);

  __asm popad
  __asm jmp returnAddress
}

char * PLUGIN_PATH = "C:\\Users\\Administrador\\source\\repos\\SpeedyTERA\\PluginExample\\Debug\\";
BOOL loadPlugins() { 
  WIN32_FIND_DATA fd = { sizeof(fd) };

  HANDLE hFind;
  char szPluginSearch[MAX_PATH] = { 0 };
  strcpy_s(szPluginSearch, PLUGIN_PATH);
  strcat_s(szPluginSearch, "*.dll");

  if (hFind = FindFirstFile(szPluginSearch, &fd)) {

    do {
      char szDLL[MAX_PATH] = { 0 };
      strcpy_s(szDLL, PLUGIN_PATH);
      strcat_s(szDLL, fd.cFileName);

      HMODULE hLib = LoadLibrary(szDLL);
      if (hLib == NULL) continue;

      FARPROC lpHook = GetProcAddress(hLib, "onBeforeEncrypt");
      if (lpHook == NULL) continue;

      cbOnBeforeEncrypt.push_back((defOnBeforeEncrypt)lpHook);

      char buf[MAX_PATH] = "[SpeedyTera] Plugin Loaded: ";
      strcat_s(buf, szDLL);
      OutputDebugString(buf);

    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
    return TRUE;
  }

  return FALSE;
}

HMODULE hDLL;
void initHooked() { //HMODULE hDLL) {
  loadPlugins();

  //---

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

  OutputDebugString("[SpeedyTera] TERA.EXE Process Hooked");
}

void initAlone() { //HMODULE hDLL) {
  char szDLL[MAX_PATH];
  GetModuleFileName(hDLL, szDLL, MAX_PATH);

  if (injectDLL(szDLL) == FALSE) {
    MessageBox(0, "[!] TERA.exe not running or not enough privileges", "SpeedyTera ERROR", MB_ICONERROR | MB_OK);
  }
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
  switch (ulReason) {
  case DLL_PROCESS_ATTACH: {
    char szPath[MAX_PATH];
    GetModuleFileName(GetModuleHandle(0), szPath, MAX_PATH);
    char *szApp = strrchr(szPath, '\\') + 1;
    //MessageBoxA(0, szApp, "DllMain", 0);
    hDLL = hModule;

    if (_stricmp(szApp, TERA_EXE) == 0) {
      //CreateThread(0, 0, (LPTHREAD_START_ROUTINE)initHooked, 0, 0, 0);
      initHooked();
    }
    else {
      //CreateThread(0, 0, (LPTHREAD_START_ROUTINE)loadPlugins, 0, 0, 0);
      initAlone();
    }

    break;
  }
  case DLL_PROCESS_DETACH:
    break;
  }

  return TRUE;
}
