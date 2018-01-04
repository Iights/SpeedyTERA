#ifdef _MSC_VER
	#pragma pack ( push, 0x4 )
#endif

/*
# ========================================================================================= #
# Function Structs
# ========================================================================================= #
*/

// Function S1Game.S1AnimNodeSequence.SetAnim
// [0x00020400] ( FUNC_Native )
struct US1AnimNodeSequence_execSetAnim_Parms
{
	struct FName                                       Sequence;                                         		// 0x0000 (0x0008) [0x0000000000000080]              ( CPF_Parm )
};

// Function S1Game.S1AudioFinishDelegate.OnAudioFinished
// [0x00020400] ( FUNC_Native )
struct US1AudioFinishDelegate_execOnAudioFinished_Parms
{
	class UAudioComponent*                             AC;                                               		// 0x0000 (0x0004) [0x0000000004000080]              ( CPF_Parm | CPF_EditInline )
};

// Function S1Game.S1GameViewportClient.PostRender
// [0x00020802] ( FUNC_Event )
struct US1GameViewportClient_eventPostRender_Parms
{
	class UCanvas*                                     Canvas;                                           		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
};

// Function S1Game.S1GameViewportClient.RenderS1UI
// [0x00020400] ( FUNC_Native )
struct US1GameViewportClient_execRenderS1UI_Parms
{
	class UCanvas*                                     CanvasObject;                                     		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
};

// Function S1Game.S1GFxEICallbackHandler.EICallback
// [0x00020400] ( FUNC_Native )
struct US1GFxEICallbackHandler_execEICallback_Parms
{
	class UGFxMovie*                                   Movie;                                            		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
	struct FString                                     Cmd;                                              		// 0x0004 (0x000C) [0x0000000000400080]              ( CPF_Parm | CPF_NeedCtorLink )
	class UGFxValue*                                   arg;                                              		// 0x0010 (0x0004) [0x0000000000000080]              ( CPF_Parm )
	unsigned long                                      ReturnValue : 1;                                  		// 0x0014 (0x0004) [0x0000000000000580] [0x00000001] ( CPF_Parm | CPF_OutParm | CPF_ReturnParm )
};

// Function S1Game.S1GFxFSCmdHandler.FSCommand
// [0x00020400] ( FUNC_Native )
struct US1GFxFSCmdHandler_execFSCommand_Parms
{
	class UGFxMovie*                                   Movie;                                            		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
	struct FString                                     Cmd;                                              		// 0x0004 (0x000C) [0x0000000000400080]              ( CPF_Parm | CPF_NeedCtorLink )
	struct FString                                     arg;                                              		// 0x0010 (0x000C) [0x0000000000400080]              ( CPF_Parm | CPF_NeedCtorLink )
	unsigned long                                      ReturnValue : 1;                                  		// 0x001C (0x0004) [0x0000000000000580] [0x00000001] ( CPF_Parm | CPF_OutParm | CPF_ReturnParm )
};

// Function S1Game.S1HUD.DrawHUD
// [0x00020002] 
struct AS1HUD_execDrawHUD_Parms
{
};

// Function S1Game.S1HUD.OutputString
// [0x00020400] ( FUNC_Native )
struct AS1HUD_execOutputString_Parms
{
	class UCanvas*                                     CanvasObject;                                     		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
};

// Function S1Game.S1PlayerCamera.UpdateViewTarget
// [0x00420002] 
struct AS1PlayerCamera_execUpdateViewTarget_Parms
{
	struct FTViewTarget                                OutVT;                                            		// 0x0000 (0x002C) [0x0000000000000180]              ( CPF_Parm | CPF_OutParm )
	float                                              DeltaTime;                                        		// 0x002C (0x0004) [0x0000000000000080]              ( CPF_Parm )
	// class ACameraActor*                             CamActor;                                         		// 0x0030 (0x0004) [0x0000000000000000]              
};

// Function S1Game.S1PlayerCamera.ApplyCameraModifiersNative
// [0x00440501] ( FUNC_Final | FUNC_Native )
struct AS1PlayerCamera_execApplyCameraModifiersNative_Parms
{
	float                                              DeltaTime;                                        		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
	struct FTPOV                                       OutPOV;                                           		// 0x0004 (0x001C) [0x0000000000000180]              ( CPF_Parm | CPF_OutParm )
};

// Function S1Game.S1PlayerCamera.ApplyCameraModifiers
// [0x00420802] ( FUNC_Event )
struct AS1PlayerCamera_eventApplyCameraModifiers_Parms
{
	float                                              DeltaTime;                                        		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
	struct FTPOV                                       OutPOV;                                           		// 0x0004 (0x001C) [0x0000000000000180]              ( CPF_Parm | CPF_OutParm )
};

// Function S1Game.S1PlayerCamera.PostBeginPlay
// [0x00020802] ( FUNC_Event )
struct AS1PlayerCamera_eventPostBeginPlay_Parms
{
};

// Function S1Game.S1PlayerController.DisplayGameMenu
// [0x00020002] 
struct AS1PlayerController_execDisplayGameMenu_Parms
{
	// class UUIInteraction*                           UIController;                                     		// 0x0000 (0x0004) [0x0000000000000000]              
};

// Function S1Game.S1PlayerController.ShowMenu
// [0x00020202] ( FUNC_Exec )
struct AS1PlayerController_execShowMenu_Parms
{
};

// Function S1Game.S1PlayerController.PlayerTick
// [0x00820802] ( FUNC_Event )
struct AS1PlayerController_eventPlayerTick_Parms
{
	float                                              DeltaTime;                                        		// 0x0000 (0x0004) [0x0000000000000080]              ( CPF_Parm )
	// struct FVector                                  CamLoc;                                           		// 0x0004 (0x000C) [0x0000000000000000]              
	// struct FVector                                  NewHandlePos;                                     		// 0x0010 (0x000C) [0x0000000000000000]              
	// struct FVector                                  X;                                                		// 0x001C (0x000C) [0x0000000000000000]              
	// struct FVector                                  Y;                                                		// 0x0028 (0x000C) [0x0000000000000000]              
	// struct FVector                                  Z;                                                		// 0x0034 (0x000C) [0x0000000000000000]              
	// struct FQuat                                    PawnQuat;                                         		// 0x0040 (0x0010) [0x0000000000000000]              
	// struct FQuat                                    NewHandleOrientation;                             		// 0x0050 (0x0010) [0x0000000000000000]              
	// struct FRotator                                 CamRot;                                           		// 0x0060 (0x000C) [0x0000000000000000]              
};

// Function S1Game.S1PlayerController.StopAltFire
// [0x00024202] ( FUNC_Exec )
struct AS1PlayerController_execStopAltFire_Parms
{
	unsigned char                                      FireModeNum;                                      		// 0x0000 (0x0001) [0x0000000000000090]              ( CPF_OptionalParm | CPF_Parm )
};

// Function S1Game.S1PlayerController.StartAltFire
// [0x00824202] ( FUNC_Exec )
struct AS1PlayerController_execStartAltFire_Parms
{
	unsigned char                                      FireModeNum;                                      		// 0x0000 (0x0001) [0x0000000000000090]              ( CPF_OptionalParm | CPF_Parm )
	// struct FVector                                  CamLoc;                                           		// 0x0004 (0x000C) [0x0000000000000000]              
	// struct FVector                                  StartShot;                                        		// 0x0010 (0x000C) [0x0000000000000000]              
	// struct FVector                                  EndShot;                                          		// 0x001C (0x000C) [0x0000000000000000]              
	// struct FVector                                  X;                                                		// 0x0028 (0x000C) [0x0000000000000000]              
	// struct FVector                                  Y;                                                		// 0x0034 (0x000C) [0x0000000000000000]              
	// struct FVector                                  Z;                                                		// 0x0040 (0x000C) [0x0000000000000000]              
	// struct FVector                                  HitLocation;                                      		// 0x004C (0x000C) [0x0000000000000000]              
	// struct FVector                                  HitNormal;                                        		// 0x0058 (0x000C) [0x0000000000000000]              
	// struct FVector                                  Extent;                                           		// 0x0064 (0x000C) [0x0000000000000000]              
	// class AActor*                                   HitActor;                                         		// 0x0070 (0x0004) [0x0000000000000000]              
	// float                                           HitDistance;                                      		// 0x0074 (0x0004) [0x0000000000000000]              
	// struct FQuat                                    PawnQuat;                                         		// 0x0078 (0x0010) [0x0000000000000000]              
	// struct FQuat                                    InvPawnQuat;                                      		// 0x0088 (0x0010) [0x0000000000000000]              
	// struct FQuat                                    ActorQuat;                                        		// 0x0098 (0x0010) [0x0000000000000000]              
	// struct FTraceHitInfo                            HitInfo;                                          		// 0x00A8 (0x001C) [0x0000000000000000]              
	// class USkeletalMeshComponent*                   SkelComp;                                         		// 0x00C4 (0x0004) [0x0000000004000000]              ( CPF_EditInline )
	// struct FRotator                                 CamRot;                                           		// 0x00C8 (0x000C) [0x0000000000000000]              
};

// Function S1Game.S1PlayerController.NextWeapon
// [0x00020202] ( FUNC_Exec )
struct AS1PlayerController_execNextWeapon_Parms
{
};

// Function S1Game.S1PlayerController.PrevWeapon
// [0x00020202] ( FUNC_Exec )
struct AS1PlayerController_execPrevWeapon_Parms
{
};

// Function S1Game.S1PlayerController.UnregisterPlayerDataStores
// [0x00020102] 
struct AS1PlayerController_execUnregisterPlayerDataStores_Parms
{
};

// Function S1Game.S1PlayerController.RegisterCustomPlayerDataStores
// [0x00080102] 
struct AS1PlayerController_execRegisterCustomPlayerDataStores_Parms
{
};

// Function S1Game.S1PlayerController.PostBeginPlay
// [0x00020902] ( FUNC_Event )
struct AS1PlayerController_eventPostBeginPlay_Parms
{
};

// Function S1Game.S1GameInfo.Login
// [0x00C20802] ( FUNC_Event )
struct AS1GameInfo_eventLogin_Parms
{
	struct FString                                     Portal;                                           		// 0x0000 (0x000C) [0x0000000000400080]              ( CPF_Parm | CPF_NeedCtorLink )
	struct FString                                     Options;                                          		// 0x000C (0x000C) [0x0000000000400080]              ( CPF_Parm | CPF_NeedCtorLink )
	struct FString                                     ErrorMessage;                                     		// 0x0018 (0x000C) [0x0000000000400180]              ( CPF_Parm | CPF_OutParm | CPF_NeedCtorLink )
	class APlayerController*                           ReturnValue;                                      		// 0x0024 (0x0004) [0x0000000000000580]              ( CPF_Parm | CPF_OutParm | CPF_ReturnParm )
	// class APlayerController*                        NewPlayer;                                        		// 0x0028 (0x0004) [0x0000000000000000]              
	// struct FRotator                                 SpawnRotation;                                    		// 0x002C (0x000C) [0x0000000000000000]              
	// struct FVector                                  SpawnLocation;                                    		// 0x0038 (0x000C) [0x0000000000000000]              
};


#ifdef _MSC_VER
	#pragma pack ( pop )
#endif