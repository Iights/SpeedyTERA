#ifdef _MSC_VER
	#pragma pack ( push, 0x4 )
#endif

/*
# ========================================================================================= #
# Function Structs
# ========================================================================================= #
*/

// Function GameFramework.GameHUD.StopDrawingChapterTitle
// [0x00020102] 
struct AGameHUD_execStopDrawingChapterTitle_Parms
{
};

// Function GameFramework.GameHUD.StartDrawingChapterTitle
// [0x00020102] 
struct AGameHUD_execStartDrawingChapterTitle_Parms
{
	struct FString                                     ChapterName;                                      		// 0x0000 (0x000C) [0x0000000000400080]              ( CPF_Parm | CPF_NeedCtorLink )
	struct FString                                     ActName;                                          		// 0x000C (0x000C) [0x0000000000400080]              ( CPF_Parm | CPF_NeedCtorLink )
	float                                              TotalDrawTime;                                    		// 0x0018 (0x0004) [0x0000000000000080]              ( CPF_Parm )
	float                                              TotalFadeTime;                                    		// 0x001C (0x0004) [0x0000000000000080]              ( CPF_Parm )
};

// Function GameFramework.GameHUD.SetHUDDrawColor
// [0x00024002] 
struct AGameHUD_execSetHUDDrawColor_Parms
{
	unsigned char                                      eColor;                                           		// 0x0000 (0x0001) [0x0000000000000080]              ( CPF_Parm )
	unsigned char                                      Alpha;                                            		// 0x0001 (0x0001) [0x0000000000000090]              ( CPF_OptionalParm | CPF_Parm )
};

// Function GameFramework.GamePawn.GetTargetFrictionCylinder
// [0x00420102] 
struct AGamePawn_execGetTargetFrictionCylinder_Parms
{
	float                                              CylinderRadius;                                   		// 0x0000 (0x0004) [0x0000000000000180]              ( CPF_Parm | CPF_OutParm )
	float                                              CylinderHeight;                                   		// 0x0004 (0x0004) [0x0000000000000180]              ( CPF_Parm | CPF_OutParm )
};


#ifdef _MSC_VER
	#pragma pack ( pop )
#endif