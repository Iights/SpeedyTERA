#include "dllmain.h"

#include "console.h"
#include "process.h"
#include "themida.h"
#include "network.h"
#include "plugin.h"

char *TERA_EXE = "TERA.exe";

HMODULE hDLL;
LPVOID teraBase;
DWORD teraSize;

extern "C" __declspec (dllexport) void __cdecl dummy(HWND hWnd, HINSTANCE hInst, LPTSTR lpCmdLine, int nCmdShow) { }

void initAlone() {
  char szDLL[MAX_PATH];
  GetModuleFileName(hDLL, szDLL, MAX_PATH);

  if (injectDLL(TERA_EXE, szDLL) == FALSE) {
    MessageBox(0, "[!] TERA.exe not running or not enough privileges", "SpeedyTera ERROR", MB_ICONERROR | MB_OK);
  }
}

void initHooked() {
  MODULEENTRY32 me = { 0 };
  getModule(GetCurrentProcessId(), TERA_EXE, me);
  teraBase = me.modBaseAddr;
  teraSize = me.modBaseSize;

  spawnConsole();
  printf("[+] SpeedyTera DEV\n");

  patchThemida();
  patchCrypto();
  loadPlugins();
  
}

void exitLibrary() {
  char szLib[MAX_PATH] = { 0 };
  GetModuleFileName(hDLL, szLib, sizeof(szLib));
  HMODULE hRef = LoadLibrary(szLib);
  FreeLibraryAndExitThread(hRef, 0);
}

void unloadAll() {
  unloadPlugins();
  restoreCrypto();
  restoreThemida();
  exitConsole();
  exitLibrary(); //todo: fix
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
  switch (ulReason) {
  case DLL_PROCESS_ATTACH: {
    DisableThreadLibraryCalls(hModule);
    hDLL = hModule;

    char szPath[MAX_PATH] = { 0 };
    GetModuleFileName(GetModuleHandle(0), szPath, MAX_PATH);
    char *szApp = strrchr(szPath, '\\') + 1;

    if (_stricmp(szApp, TERA_EXE) == 0) {
      initHooked();
    }
    else {
      initAlone();
    }

    break;
  }
  case DLL_PROCESS_DETACH:
    if(hasConsole) exitConsole();
    break;
  }

  return TRUE;
}
