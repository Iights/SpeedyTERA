#pragma once
#pragma pack(push, 1)
template<class T> struct TArray {
  T* Data;
  int Count;
  int Max;
};

struct FNameEntry {
  char unk[0x10];
  char Name[0x10];
};

struct FName {
  int Index;
  char unk[0x4];
};

/*struct FPointer {
  int Dummy;
};

struct FQWord {
  int A;
  int B;
};*/

struct FScriptDelegate {
  char unk[0xC];
};

struct FString : public TArray<wchar_t> {};
#pragma pack(pop, 1)

#include "SDK\Core_structs.h"
#include "SDK\Core_classes.h"
#include "SDK\Core_f_structs.h"
#include "SDK\Core_functions.h"
#include "SDK\Engine_structs.h"
#include "SDK\Engine_classes.h"
#include "SDK\Engine_f_structs.h"
#include "SDK\Engine_functions.h"
#include "SDK\GameFramework_structs.h"
#include "SDK\GameFramework_classes.h"
#include "SDK\GameFramework_f_structs.h"
#include "SDK\GameFramework_functions.h"
#include "SDK\GFxUI_structs.h"
#include "SDK\GFxUI_classes.h"
#include "SDK\GFxUI_f_structs.h"
#include "SDK\GFxUI_functions.h"
#include "SDK\ALAudio_structs.h"
#include "SDK\ALAudio_classes.h"
#include "SDK\ALAudio_f_structs.h"
#include "SDK\ALAudio_functions.h"
#include "SDK\WinDrv_structs.h"
#include "SDK\WinDrv_classes.h"
#include "SDK\WinDrv_f_structs.h"
#include "SDK\WinDrv_functions.h"
#include "SDK\S1Game_structs.h"
#include "SDK\S1Game_classes.h"
#include "SDK\S1Game_f_structs.h"
#include "SDK\S1Game_functions.h"
#include "SDK\UnrealScriptTest_structs.h"
#include "SDK\UnrealScriptTest_classes.h"
#include "SDK\UnrealScriptTest_f_structs.h"
#include "SDK\UnrealScriptTest_functions.h"
