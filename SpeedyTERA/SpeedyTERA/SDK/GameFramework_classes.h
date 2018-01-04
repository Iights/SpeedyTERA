#ifdef _MSC_VER
	#pragma pack ( push, 0x4 )
#endif

/*
# ========================================================================================= #
# Constants
# ========================================================================================= #
*/


/*
# ========================================================================================= #
# Enums
# ========================================================================================= #
*/

// Enum GameFramework.GameHUD.EGameHUDColor
enum EGameHUDColor
{
	GHD_WHITE                                          = 0,
	GHD_BLACK                                          = 1,
	GHD_MAX                                            = 2
};

// Enum GameFramework.GameSkelCtrl_Recoil.ERecoilStart
enum ERecoilStart
{
	ERS_Zero                                           = 0,
	ERS_Random                                         = 1,
	ERS_MAX                                            = 2
};


/*
# ========================================================================================= #
# Classes
# ========================================================================================= #
*/

// Class GameFramework.GameHUD
// 0x0024 (0x0468 - 0x0444)
class AGameHUD : public AHUD
{
public:
	float                                              TotalTitleDrawTime;                               		// 0x0444 (0x0004) [0x0000000000000000]              
	float                                              TotalTitleFadeTime;                               		// 0x0448 (0x0004) [0x0000000000000000]              
	float                                              TitleDrawStartTime;                               		// 0x044C (0x0004) [0x0000000000000000]              
	struct FString                                     ChapterTitleString;                               		// 0x0450 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	struct FString                                     ActTitleString;                                   		// 0x045C (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

	void StopDrawingChapterTitle ( );
	void StartDrawingChapterTitle ( struct FString ChapterName, struct FString ActName, float TotalDrawTime, float TotalFadeTime );
	void SetHUDDrawColor ( unsigned char eColor, unsigned char Alpha );
};

UClass* AGameHUD::pClassPointer = NULL;

// Class GameFramework.GamePawn
// 0x0000 (0x03BC - 0x03BC)
class AGamePawn : public APawn
{
public:

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

	void GetTargetFrictionCylinder ( float* CylinderRadius, float* CylinderHeight );
};

UClass* AGamePawn::pClassPointer = NULL;

// Class GameFramework.GamePlayerController
// 0x0000 (0x05A8 - 0x05A8)
class AGamePlayerController : public APlayerController
{
public:

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

};

UClass* AGamePlayerController::pClassPointer = NULL;

// Class GameFramework.GamePlayerInput
// 0x0000 (0x0164 - 0x0164)
class UGamePlayerInput : public UPlayerInput
{
public:

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

};

UClass* UGamePlayerInput::pClassPointer = NULL;

// Class GameFramework.GameProjectile
// 0x0000 (0x01FC - 0x01FC)
class AGameProjectile : public AProjectile
{
public:

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

};

UClass* AGameProjectile::pClassPointer = NULL;

// Class GameFramework.GameTypes
// 0x0000 (0x003C - 0x003C)
class UGameTypes : public UObject
{
public:

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

};

UClass* UGameTypes::pClassPointer = NULL;

// Class GameFramework.GameVehicle
// 0x0000 (0x0540 - 0x0540)
class AGameVehicle : public ASVehicle
{
public:

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

};

UClass* AGameVehicle::pClassPointer = NULL;

// Class GameFramework.GameWeapon
// 0x0000 (0x02B0 - 0x02B0)
class AGameWeapon : public AWeapon
{
public:

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

};

UClass* AGameWeapon::pClassPointer = NULL;

// Class GameFramework.GameSkelCtrl_Recoil
// 0x007C (0x0110 - 0x0094)
class UGameSkelCtrl_Recoil : public USkelControlBase
{
public:
	unsigned long                                      bBoneSpaceRecoil : 1;                             		// 0x0094 (0x0004) [0x0000000000000001] [0x00000001] ( CPF_Edit )
	unsigned long                                      bPlayRecoil : 1;                                  		// 0x0094 (0x0004) [0x0000000000002001] [0x00000002] ( CPF_Edit | CPF_Transient )
	unsigned long                                      bOldPlayRecoil : 1;                               		// 0x0094 (0x0004) [0x0000000000002000] [0x00000004] ( CPF_Transient )
	unsigned long                                      bApplyControl : 1;                                		// 0x0094 (0x0004) [0x0000000000002000] [0x00000008] ( CPF_Transient )
	struct FRecoilDef                                  Recoil;                                           		// 0x0098 (0x0070) [0x0000000000000001]              ( CPF_Edit )
	struct FVector2D                                   Aim;                                              		// 0x0108 (0x0008) [0x0000000000000001]              ( CPF_Edit )

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

};

UClass* UGameSkelCtrl_Recoil::pClassPointer = NULL;


#ifdef _MSC_VER
	#pragma pack ( pop )
#endif