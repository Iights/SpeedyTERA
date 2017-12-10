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

typedef void(__cdecl * defHookCallback)(char *, size_t);
std::vector<defHookCallback> cbOnBeforeEncrypt = {};
std::vector<defHookCallback> cbOnAfterEncrypt = {};
std::vector<defHookCallback> cbOnBeforeDecrypt = {};
std::vector<defHookCallback> cbOnAfterDecrypt = {};

char * encBuffer;
size_t encSize;
char * decBuffer;
size_t decSize;

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
    mov eax, dword ptr ss : [esp + 0x0c]
    mov[encSize], eax
    mov eax, dword ptr ss : [esp + 0x04]
    mov[retnEncAddr], eax
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
    mov eax, dword ptr ss : [esp + 0x0c]
    mov[decSize], eax
    mov eax, dword ptr ss : [esp + 0x04]
    mov[retnDecAddr], eax
    pop eax

    pushad
    call onBeforeDecrypt
    popad

    add esp, 4
    call[realDecrypt]

    pushad
    call onAfterDecrypt
    popad

    push retnDecAddr
    retn
  }
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

      FARPROC lpHook;
      lpHook = GetProcAddress(hLib, "onBeforeEncrypt");
      if (lpHook != NULL) cbOnBeforeEncrypt.push_back((defHookCallback)lpHook);
      lpHook = GetProcAddress(hLib, "onAfterEncrypt");
      if (lpHook != NULL) cbOnAfterEncrypt.push_back((defHookCallback)lpHook);

      lpHook = GetProcAddress(hLib, "onBeforeDecrypt");
      if (lpHook != NULL) cbOnBeforeDecrypt.push_back((defHookCallback)lpHook);
      lpHook = GetProcAddress(hLib, "onAfterDecrypt");
      if (lpHook != NULL) cbOnAfterDecrypt.push_back((defHookCallback)lpHook);

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

  realEncrypt = TeraBase + ADDR_ENCRYPT_FN1;
  realDecrypt = TeraBase + ADDR_ENCRYPT_FN2;

  //-- enc

  DWORD lpEncJmp = (DWORD)&encryptHook;
  DWORD lpEncRel = *((DWORD *)(lpEncJmp + 1));
  DWORD lpEncAbs = lpEncJmp + lpEncRel + 5;

  DWORD lpAbsEnc1 = lpEncAbs - (TeraBase + ADDR_CALL_ENCRYPT_FN1_1) - 5;
  DWORD lpAbsEnc2 = lpEncAbs - (TeraBase + ADDR_CALL_ENCRYPT_FN1_2) - 5;

  *((DWORD *)(TeraBase + ADDR_CALL_ENCRYPT_FN1_1 + 1)) = lpAbsEnc1;
  *((DWORD *)(TeraBase + ADDR_CALL_ENCRYPT_FN1_2 + 1)) = lpAbsEnc2;

  //-- dec

  DWORD lpDecJmp = (DWORD)&decryptHook;
  DWORD lpDecRel = *((DWORD *)(lpDecJmp + 1));
  DWORD lpDecAbs = lpDecJmp + lpDecRel + 5;

  DWORD lpAbsDec1 = lpDecAbs - (TeraBase + ADDR_CALL_ENCRYPT_FN2_1) - 5;
  DWORD lpAbsDec2 = lpDecAbs - (TeraBase + ADDR_CALL_ENCRYPT_FN2_2) - 5;

  *((DWORD *)(TeraBase + ADDR_CALL_ENCRYPT_FN2_1 + 1)) = lpAbsDec1;
  *((DWORD *)(TeraBase + ADDR_CALL_ENCRYPT_FN2_2 + 1)) = lpAbsDec2;

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
    //MessageBox(0, szApp, "DllMain", 0);
    hDLL = hModule;

    if (_stricmp(szApp, TERA_EXE) == 0) {
      //CreateThread(0, 0, (LPTHREAD_START_ROUTINE)initHooked, 0, 0, 0);
      initHooked();
    }
    else {
      initAlone();
    }

    break;
  }
  case DLL_PROCESS_DETACH:
    break;
  }

  return TRUE;
}
