#include "dllmain.h"
#include "engine.h"

#include "hook.h"
#include "sdk.h"

#pragma pack(push, 1)
struct UObjectEx {
  struct FPointer VfTableObject;
  int ObjectInternalInteger;
  struct FQWord ObjectFlags;
  struct FPointer HashNext;
  struct FPointer HashOuterNext;
  struct FPointer StateFrame;
  struct UObjectEx* Linker;
  struct FPointer LinkerIndex;
  int NetIndex;
  struct UObjectEx* Outer;
  struct FName Name;
  struct VClass* Class;
  struct UObjectEx* ObjectArchetype;
};
#pragma pack(pop, 1)

TArray<UObjectEx*> *GObjects = NULL;
TArray<FNameEntry*> *GNames = NULL;

char* getName(int idx) {
  if (idx >= 0 && idx <= GNames->Count)
    return GNames->Data[idx]->Name;
  return "(null)";
};

char *getFullName(UObjectEx *obj) {
  if (obj->Class && obj->Outer)
  {
    static char cOutBuffer[512];

    char cTmpBuffer[512];

    strcpy_s(cOutBuffer, getName(obj->Name.Index));

    for (UObjectEx* pOuter = obj->Outer; pOuter; pOuter = pOuter->Outer)
    {
      strcpy_s(cTmpBuffer, getName(pOuter->Name.Index));
      strcat_s(cTmpBuffer, ".");

      size_t len1 = strlen(cTmpBuffer);
      size_t len2 = strlen(cOutBuffer);

      memmove(cOutBuffer + len1, cOutBuffer, len1 + len2 + 1);
      memcpy(cOutBuffer, cTmpBuffer, len1);
    }
    
    UObjectEx* cls = (UObjectEx*)obj->Class;
    strcpy_s(cTmpBuffer, getName(cls->Name.Index));
    strcat_s(cTmpBuffer, " ");

    size_t len1 = strlen(cTmpBuffer);
    size_t len2 = strlen(cOutBuffer);

    memmove(cOutBuffer + len1, cOutBuffer, len1 + len2 + 1);
    memcpy(cOutBuffer, cTmpBuffer, len1);

    return cOutBuffer;
  }

  return "(null)";
}

void dumpObjects() {
  FILE *fp = NULL;
  fopen_s(&fp, "objects.log", "w");

  for (int i = 0; i < GObjects->Count; i++) {
    if (!GObjects->Data[i]) { continue; }

    UObjectEx *obj = GObjects->Data[i];
    fprintf(fp, "[%06i:%06i] %-50s 0x%X\n", i, obj->Name.Index, getFullName(obj), (DWORD)GObjects->Data[i]);
  }

  fclose(fp);
}

void dumpObjectsByClass(char *name) {
  for (int i = 0; i < GObjects->Count; i++) {
    if (!GObjects->Data[i]) { continue; }

    UObjectEx *obj = GObjects->Data[i];
    UObjectEx *cls = (UObjectEx*)obj->Class;
    if (_stricmp(getName(cls->Name.Index), name) == 0)
      printf("[%06i:%06i] %-50s 0x%X\n", i, obj->Name.Index, getFullName(obj), (DWORD)GObjects->Data[i]);
  }
}

UObjectEx *findObject(char *name) {
  for (int i = 0; i < GObjects->Count; i++) {
    if (!GObjects->Data[i]) { continue; }

    UObjectEx *obj = GObjects->Data[i];
    if (_stricmp(getFullName(obj), name) == 0)
      return obj;
  }

  return NULL;
}

void printRaw(void *ptr, size_t size) {
  char *printme = (char*)ptr;
  for (size_t i = 0; i < size; i++) {
    printf("%02x ", *printme++);
    if(!(i % 4)) printf("\n");
  }
}

void InitCore() {
  GObjects = (TArray<UObjectEx*>*)(*(DWORD*)(dwFindPattern((DWORD)teraBase, teraSize, (BYTE*)GOBJECTS_PATTERN, GOBJECTS_MASK) + GOBJECTS_OFFSET)); //0x0264A1CC;
  GNames = (TArray<FNameEntry*>*)(*(DWORD*)(dwFindPattern((DWORD)teraBase, teraSize, (BYTE*)GNAMES_PATTERN, GNAMES_MASK) + GNAMES_OFFSET)); //0x02603D54

  /**/

  //dumpObjects();
  /*
  auto engine = (UGameEngine*)findObject("GameEngine Transient.GameEngine");
  printf("GameEngine => %08X\n", (DWORD)engine);
  printf("GameEngine->MaxSmoothedFrameRate => %.2f\n", engine->MaxSmoothedFrameRate);
  printf("GameEngine->MinSmoothedFrameRate => %.2f\n", engine->MinSmoothedFrameRate);
  */

  auto camera = (AS1PlayerCamera*)findObject("S1PlayerCamera Start.TheWorld.PersistentLevel.S1PlayerCamera");
  printf("S1PlayerCamera => %08X\n", (DWORD)camera);
  printf("S1PlayerCamera->DefaultFOV => %.2f\n", camera->DefaultFOV);

  UFunction* pFnGetFOVAngle = (UFunction*)findObject("Function Engine.Camera.GetFOVAngle");
  printf("pFnGetFOVAngle => %08X\n", (DWORD)pFnGetFOVAngle);

  ACamera_execGetFOVAngle_Parms GetFOVAngle_Parms;
  camera->ProcessEvent(pFnGetFOVAngle, &GetFOVAngle_Parms, NULL);
  printf("S1PlayerCamera->GetFOVAngle() => %.2f\n", GetFOVAngle_Parms.ReturnValue);


  //auto actor = (AS1Actor*)findObject("S1Actor Start.TheWorld.PersistentLevel.S1Actor");
  //auto aeroActor = (AS1AeroActor*)findObject("S1AeroActor Start.TheWorld.PersistentLevel.S1AeroActor");

  /*
  auto world = (UWorld*)findObject("World Start.TheWorld");
  auto level = world->PersistentLevel; //(ULevel*)findObject("Level Start.TheWorld.PersistentLevel");
  auto actors = level->Actors;
  
  for (int i = 0; i < actors.Count; i++) {
    if (!actors.Data[i]) { continue; }

    auto obj = actors.Data[i];
    if (_stricmp(getName(obj->Class->Name.Index), "S1SkeletalMeshActor") == 0) {
      auto actor = (AS1SkeletalMeshActor*)obj;
      printf("Actor[%06i] => (%.2f, %.2f, %.2f) %s\n", i, obj->Location.X, obj->Location.Y, obj->Location.Z, getFullName((UObjectEx*)obj));
    }
  }
  */

  

}
