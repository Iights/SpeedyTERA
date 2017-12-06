#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>

#include "dllmain.h"

char *TERA_EXE = "TERA.exe";
extern "C" __declspec (dllexport) void __cdecl dummy(HWND hWnd, HINSTANCE hInst, LPTSTR lpCmdLine, int nCmdShow) { }

DWORD getPID(char *szExe) {
  DWORD pID = 0;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  PROCESSENTRY32 pe = { sizeof(pe) };
  if(Process32First(hSnapshot, &pe)) {
    do {
      if(_stricmp(pe.szExeFile, szExe) == 0) {
        pID = pe.th32ProcessID;
        break;
      }
    } while(Process32Next(hSnapshot, &pe));
  }

  CloseHandle(hSnapshot);
  return pID;
}

BOOL injectDLL(char *szDLL) {
  DWORD pID = getPID(TERA_EXE);
  if(pID == 0) return FALSE;

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
  if(hProcess == NULL)  return FALSE;

  SIZE_T len = strlen(szDLL);
  LPVOID pName = VirtualAllocEx(hProcess, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if(pName == NULL) return FALSE;

  BOOL bStatus = WriteProcessMemory(hProcess, pName, szDLL, len, nullptr);
  if(bStatus == 0) return FALSE;

  HMODULE hKernel = GetModuleHandle("kernel32.dll");
  FARPROC pLoadLibrary = GetProcAddress(hKernel, "LoadLibraryA");
  if(pLoadLibrary == NULL) return FALSE;

  HANDLE hThreadId = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), pName, NULL, nullptr);
  if(hThreadId == NULL) return FALSE;

  //WaitForSingleObject(hThreadId, INFINITE);

  VirtualFreeEx(hProcess, pName, len, MEM_RELEASE);
  CloseHandle(hProcess);

  return TRUE;
}

int encrypt(int unk1, DWORD unk2) {
  
  return 4;
}

void initHooked() {
  MessageBox(0, "IM AT TERA.EXE", 0, 0);
  
  memcpy((LPVOID)ADDR_CALL_ENCRYPT_FN1_1+1, (LPVOID)&encrypt, 4);
  
  MessageBox(0, "HOOKED TERA.EXE", 0, 0);
}

void initAlone(HMODULE hDLL) {
  char szDLL[MAX_PATH];
  GetModuleFileName(hDLL, szDLL, MAX_PATH);

  if(injectDLL(szDLL) == FALSE) {
    MessageBox(0, "[!] tera.exe not running or not enough privileges", "SpeedyTera ERROR", MB_ICONERROR | MB_OK);
  }

}

int __stdcall DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
  switch(ulReason) {
    case DLL_PROCESS_ATTACH: {
      char szPath[MAX_PATH];
      GetModuleFileName(GetModuleHandle(0), szPath, MAX_PATH);
      char *szApp = strrchr(szPath, '\\') + 1;
      //MessageBoxA(0, szApp, "DllMain", 0);

      if(_stricmp(szApp, TERA_EXE) == 0) {
        initHooked();
      }
      else {
        initAlone(hModule);
      }

      break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return 1;
}
