#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <vector>

/*
TERA.exe+15626B0 - 55                    - push ebp
TERA.exe+15626B1 - 8B EC                 - mov ebp,esp
TERA.exe+15626B3 - 83 EC 28              - sub esp,28 { 40 }
TERA.exe+15626B6 - 8B 41 04              - mov eax,[ecx+04]
TERA.exe+15626B9 - 8B 55 0C              - mov edx,[ebp+0C]
TERA.exe+15626BC - 53                    - push ebx
TERA.exe+15626BD - 56                    - push esi
TERA.exe+15626BE - 57                    - push edi
TERA.exe+15626BF - 8D 79 04              - lea edi,[ecx+04]
TERA.exe+15626C2 - 89 7D DC              - mov [ebp-24],edi
TERA.exe+15626C5 - 85 C0                 - test eax,eax
...

TERA.exe+1561030 - 55                    - push ebp
TERA.exe+1561031 - 8B EC                 - mov ebp,esp
TERA.exe+1561033 - 83 EC 28              - sub esp,28 { 40 }
TERA.exe+1561036 - 8B 41 04              - mov eax,[ecx+04]
TERA.exe+1561039 - 8B 55 0C              - mov edx,[ebp+0C]
TERA.exe+156103C - 53                    - push ebx
TERA.exe+156103D - 56                    - push esi
TERA.exe+156103E - 57                    - push edi
TERA.exe+156103F - 8D 79 04              - lea edi,[ecx+04]
TERA.exe+1561042 - 89 7D DC              - mov [ebp-24],edi
TERA.exe+1561045 - 85 C0                 - test eax,eax
...

01961AE4 - E8 C70B0000 - CALL 019626B0
01962A02 - E8 A9FCFFFF - CALL 019626B0

01961382 - E8 A9FCFFFF - CALL 01961030
01961BD1 - E8 5AF4FFFF - CALL 01961030

----------

speedytera.dll+116B0 - 55                    - push ebp
speedytera.dll+116B1 - 8B EC                 - mov ebp,esp
speedytera.dll+116B3 - 81 EC C0000000        - sub esp,000000C0 { 192 }
speedytera.dll+116B9 - 53                    - push ebx
speedytera.dll+116BA - 56                    - push esi
speedytera.dll+116BB - 57                    - push edi
speedytera.dll+116BC - 8D BD 40FFFFFF        - lea edi,[ebp-000000C0]
speedytera.dll+116C2 - B9 30000000           - mov ecx,00000030 { 48 }
speedytera.dll+116C7 - B8 CCCCCCCC           - mov eax,CCCCCCCC { -858993460 }
speedytera.dll+116CC - F3 AB                 - repe stosd
speedytera.dll+116CE - 8B F4                 - mov esi,esp


speedytera.dll+116E8 - 8B F4                 - mov esi,esp
speedytera.dll+116EA - 8B 45 0C              - mov eax,[ebp+0C]
speedytera.dll+116ED - 50                    - push eax
speedytera.dll+116EE - 8B 4D 08              - mov ecx,[ebp+08]
speedytera.dll+116F1 - 51                    - push ecx
speedytera.dll+116F2 - FF 15 3891B764        - call dword ptr [speedytera.dll+19138] { ->TERA.exe+15626B0 }
speedytera.dll+116F8 - 83 C4 08              - add esp,08 { 8 }
speedytera.dll+116FB - 3B F4                 - cmp esi,esp


*/

#define ADDR_ENCRYPT_FN1 (DWORD)0x015626B0
#define ADDR_CALL_ENCRYPT_FN1_1 (DWORD)0x01561AE4
#define ADDR_CALL_ENCRYPT_FN1_2 (DWORD)0x01562A02

#define ADDR_ENCRYPT_FN2 (DWORD)0x01561030
#define ADDR_CALL_ENCRYPT_FN2_1 (DWORD)0x01561382
#define ADDR_CALL_ENCRYPT_FN2_2 (DWORD)0x01561BD1

#define ADDR_NET_BUFFER (DWORD)0x022D3E38
