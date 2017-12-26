#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <vector>

extern HMODULE hDLL;
extern LPVOID teraBase;
extern DWORD teraSize;

void unloadAll();
