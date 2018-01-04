#ifdef _MSC_VER
	#pragma pack ( push, 0x4 )
#endif

/*
# ========================================================================================= #
# Script Structs
# ========================================================================================= #
*/

// ScriptStruct S1Game.S1AnimNodeBlend.S1AnimPlayInfo
// 0x0034
struct FS1AnimPlayInfo
{
	unsigned char                                      AnimType;                                         		// 0x0000 (0x0001) [0x0000000000000000]              
	struct FName                                       AnimName;                                         		// 0x0004 (0x0008) [0x0000000000000000]              
	float                                              fRate;                                            		// 0x000C (0x0004) [0x0000000000000000]              
	float                                              fDuration;                                        		// 0x0010 (0x0004) [0x0000000000000000]              
	float                                              fBlendInTime;                                     		// 0x0014 (0x0004) [0x0000000000000000]              
	float                                              fRootMotionXYRate;                                		// 0x0018 (0x0004) [0x0000000000000000]              
	float                                              fRootMotionZRate;                                 		// 0x001C (0x0004) [0x0000000000000000]              
	float                                              fScale;                                           		// 0x0020 (0x0004) [0x0000000000000000]              
	float                                              fRootMotionDistance;                              		// 0x0024 (0x0004) [0x0000000000000000]              
	float                                              fStartTime;                                       		// 0x0028 (0x0004) [0x0000000000000000]              
	unsigned long                                      bLooping : 1;                                     		// 0x002C (0x0004) [0x0000000000000000] [0x00000001] 
	unsigned long                                      bRootMotion : 1;                                  		// 0x002C (0x0004) [0x0000000000000000] [0x00000002] 
	unsigned long                                      bRotateMotion : 1;                                		// 0x002C (0x0004) [0x0000000000000000] [0x00000004] 
	unsigned long                                      bLast : 1;                                        		// 0x002C (0x0004) [0x0000000000000000] [0x00000008] 
	unsigned long                                      bRemainForDuration : 1;                           		// 0x002C (0x0004) [0x0000000000000000] [0x00000010] 
	int                                                nToolId;                                          		// 0x0030 (0x0004) [0x0000000000000000]              
};

// ScriptStruct S1Game.S1MatineeActorBase.SkelPartData
// 0x003C
struct FSkelPartData
{
	class USkeletalMesh*                               Mesh;                                             		// 0x0000 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	struct FName                                       AttachBone;                                       		// 0x0004 (0x0008) [0x0000000000000001]              ( CPF_Edit )
	struct FLinearColor                                ColorVar;                                         		// 0x000C (0x0010) [0x0000000000000001]              ( CPF_Edit )
	class UTexture2D*                                  DiffuseMap;                                       		// 0x001C (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class UTexture2D*                                  SpecularMap;                                      		// 0x0020 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class UTexture2D*                                  NormalMap;                                        		// 0x0024 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	TArray< struct FString >                           Materials;                                        		// 0x0028 (0x000C) [0x0000000000402001]              ( CPF_Edit | CPF_Transient | CPF_NeedCtorLink )
	class USkeletalMeshComponent*                      Comp;                                             		// 0x0034 (0x0004) [0x0000000004082008]              ( CPF_ExportObject | CPF_Transient | CPF_Component | CPF_EditInline )
	unsigned long                                      IsVisible : 1;                                    		// 0x0038 (0x0004) [0x0000000000002000] [0x00000001] ( CPF_Transient )
};

// ScriptStruct S1Game.S1MatineeActorBase.StaticPartData
// 0x0034
struct FStaticPartData
{
	class UStaticMesh*                                 Mesh;                                             		// 0x0000 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	struct FName                                       AttachBone;                                       		// 0x0004 (0x0008) [0x0000000000000001]              ( CPF_Edit )
	float                                              Scale;                                            		// 0x000C (0x0004) [0x0000000000000001]              ( CPF_Edit )
	struct FLinearColor                                ColorVar;                                         		// 0x0010 (0x0010) [0x0000000000000001]              ( CPF_Edit )
	class UTexture2D*                                  DiffuseMap;                                       		// 0x0020 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class UTexture2D*                                  SpecularMap;                                      		// 0x0024 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class UTexture2D*                                  NormalMap;                                        		// 0x0028 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class UStaticMeshComponent*                        Comp;                                             		// 0x002C (0x0004) [0x0000000004082008]              ( CPF_ExportObject | CPF_Transient | CPF_Component | CPF_EditInline )
	unsigned long                                      IsVisible : 1;                                    		// 0x0030 (0x0004) [0x0000000000002000] [0x00000001] ( CPF_Transient )
};

// ScriptStruct S1Game.S1MatineeActorBase.S1SkelPartData
// 0x0060
struct FS1SkelPartData
{
	struct FVector                                     PvPos;                                            		// 0x0000 (0x000C) [0x0000000000102000]              ( CPF_Transient )
	struct FRotator                                    DvRot;                                            		// 0x000C (0x000C) [0x0000000000102000]              ( CPF_Transient )
	struct FVector                                     DvScale;                                          		// 0x0018 (0x000C) [0x0000000000102000]              ( CPF_Transient )
	class USkeletalMesh*                               Mesh;                                             		// 0x0024 (0x0004) [0x0000000000102000]              ( CPF_Transient )
	struct FName                                       AttachBone;                                       		// 0x0028 (0x0008) [0x0000000000102000]              ( CPF_Transient )
	struct FLinearColor                                ColorVar;                                         		// 0x0030 (0x0010) [0x0000000000102000]              ( CPF_Transient )
	class UTexture2D*                                  DiffuseMap;                                       		// 0x0040 (0x0004) [0x0000000000102000]              ( CPF_Transient )
	class UTexture2D*                                  SpecularMap;                                      		// 0x0044 (0x0004) [0x0000000000102000]              ( CPF_Transient )
	class UTexture2D*                                  NormalMap;                                        		// 0x0048 (0x0004) [0x0000000000102000]              ( CPF_Transient )
	TArray< struct FString >                           Materials;                                        		// 0x004C (0x000C) [0x0000000000502000]              ( CPF_Transient | CPF_NeedCtorLink )
	class USkeletalMeshComponent*                      Comp;                                             		// 0x0058 (0x0004) [0x0000000004182008]              ( CPF_ExportObject | CPF_Transient | CPF_Component | CPF_EditInline )
	unsigned long                                      IsVisible : 1;                                    		// 0x005C (0x0004) [0x0000000000102000] [0x00000001] ( CPF_Transient )
};

// ScriptStruct S1Game.S1MatineeActorBase.FaceCustomizeData
// 0x0018
struct FFaceCustomizeData
{
	int                                                CustomDataLow;                                    		// 0x0000 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	int                                                CustomDataHigh;                                   		// 0x0004 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	TArray< unsigned char >                            BoneData;                                         		// 0x0008 (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	class UTexture2D*                                  DecalTexture;                                     		// 0x0014 (0x0004) [0x0000000000000001]              ( CPF_Edit )
};

// ScriptStruct S1Game.S1MatineeActorBase.BodyCustomizeData
// 0x0010
struct FBodyCustomizeData
{
	int                                                CustomData;                                       		// 0x0000 (0x0004) [0x0000000000100001]              ( CPF_Edit )
	TArray< float >                                    BoneData;                                         		// 0x0004 (0x000C) [0x0000000000500001]              ( CPF_Edit | CPF_NeedCtorLink )
};

// ScriptStruct S1Game.S1ParentSkeletalMeshComponent.S1PSMCBone
// 0x0018
struct FS1PSMCBone
{
	TArray< struct FName >                             AnimSetNames;                                     		// 0x0000 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	TArray< int >                                      TrackOffsets;                                     		// 0x000C (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
};

// ScriptStruct S1Game.S1SkelControlWeapon.BoneAtom
// 0x0020
struct US1SkelControlWeapon_FBoneAtom
{
	struct FQuat                                       Rotation;                                         		// 0x0000 (0x0010) [0x0000000000000000]              
	struct FVector                                     Translation;                                      		// 0x0010 (0x000C) [0x0000000000000000]              
	float                                              Scale;                                            		// 0x001C (0x0004) [0x0000000000000000]              
};


#ifdef _MSC_VER
	#pragma pack ( pop )
#endif