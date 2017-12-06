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

typedef DWORD(__cdecl * defEncrypt)(char *, int, DWORD, DWORD);
defEncrypt _encrypt;

DWORD __cdecl encrypt(char *buffer, int size, DWORD unk1, DWORD unk2) {
	/*char buf[255];
	sprintf_s(buf, "%04X", unk1);
	MessageBox(0, buf, 0, 0);
	sprintf_s(buf, "%04X", unk2);
	MessageBox(0, buf, 0, 0);
	*/
	return _encrypt(buffer, size, unk1, unk2);
}

void initHooked(HMODULE hDLL) {
  DWORD pID = getPID(TERA_EXE);

  MODULEENTRY32 me;
  getModule(pID, TERA_EXE, me);
  DWORD TeraBase = (DWORD)me.modBaseAddr;

  /**/

  DWORD lpEncrypt = (DWORD)&encrypt;
  _encrypt = defEncrypt(TeraBase + ADDR_ENCRYPT_FN1);

  DWORD lpAbsEncrypt1_1 = lpEncrypt - (TeraBase + ADDR_CALL_ENCRYPT_FN1_1) - 5;
  DWORD lpAbsEncrypt1_2 = lpEncrypt - (TeraBase + ADDR_CALL_ENCRYPT_FN1_2) - 5;
  memcpy((LPVOID)(TeraBase + ADDR_CALL_ENCRYPT_FN1_1 + 1), &lpAbsEncrypt1_1, 4);
  memcpy((LPVOID)(TeraBase + ADDR_CALL_ENCRYPT_FN1_2 + 1), &lpAbsEncrypt1_2, 4);

  DWORD lpAbsEncrypt2_1 = lpEncrypt - (TeraBase + ADDR_CALL_ENCRYPT_FN2_1) - 5;
  DWORD lpAbsEncrypt2_2 = lpEncrypt - (TeraBase + ADDR_CALL_ENCRYPT_FN2_2) - 5;
  memcpy((LPVOID)(TeraBase + ADDR_CALL_ENCRYPT_FN2_1 + 1), &lpAbsEncrypt2_1, 4);
  memcpy((LPVOID)(TeraBase + ADDR_CALL_ENCRYPT_FN2_2 + 1), &lpAbsEncrypt2_2, 4);

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
        initHooked(hModule);
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
