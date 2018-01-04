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

// Enum S1Game.S1AnimNodeBlend.ES1AnimType
enum ES1AnimType
{
	S1ANIM_NONE                                        = 0,
	S1ANIM_ACTION                                      = 1,
	S1ANIM_LIFE                                        = 2,
	S1ANIM_SOCIAL                                      = 3,
	S1ANIM_MOVE_OR_WAIT                                = 4,
	S1ANIM_MOVE_ONLY                                   = 5,
	S1ANIM_WAIT_ONLY                                   = 6,
	S1ANIM_BARRACK                                     = 7,
	S1ANIM_PENDING                                     = 8,
	S1ANIM_MAX                                         = 9
};

// Enum S1Game.S1ChannelVolume.ChannelType
enum ChannelType
{
	Channel                                            = 0,
	Channel01                                          = 1,
	Channel02                                          = 2,
	Channel03                                          = 3,
	Channel04                                          = 4,
	Channel05                                          = 5,
	Channel06                                          = 6,
	Channel07                                          = 7,
	Channel08                                          = 8,
	Channel09                                          = 9,
	Channel10                                          = 10,
	Channel11                                          = 11,
	Channel12                                          = 12,
	Channel13                                          = 13,
	Channel14                                          = 14,
	Channel15                                          = 15,
	Channel16                                          = 16,
	Channel17                                          = 17,
	Channel18                                          = 18,
	Channel19                                          = 19,
	Channel20                                          = 20,
	Channel21                                          = 21,
	Channel22                                          = 22,
	Channel23                                          = 23,
	Channel24                                          = 24,
	Channel25                                          = 25,
	Channel26                                          = 26,
	Channel27                                          = 27,
	Channel28                                          = 28,
	Channel_MAX                                        = 29
};

// Enum S1Game.S1MusicVolume.MusicChannel
enum MusicChannel
{
	MUSIC_CHANNEL_BGM                                  = 0,
	MUSIC_CHANNEL_AMBIENT                              = 1,
	MUSIC_CHANNEL_MAX                                  = 2
};

// Enum S1Game.S1MatineeActorBase.MatineeRace
enum MatineeRace
{
	RACE_HUMAN                                         = 0,
	RACE_HIGHELF                                       = 1,
	RACE_AMAN                                          = 2,
	RACE_CASTANIC                                      = 3,
	RACE_POPORI                                        = 4,
	RACE_BARAKA                                        = 5,
	RACE_MAX                                           = 6
};

// Enum S1Game.S1MatineeActorBase.MatineeGender
enum MatineeGender
{
	GENDER_MALE                                        = 0,
	GENDER_FEMALE                                      = 1,
	GENDER_MAX                                         = 2
};

// Enum S1Game.S1MatineeActorBase.MatineeClass
enum MatineeClass
{
	CLASS_WARRIOR                                      = 0,
	CLASS_LANCER                                       = 1,
	CLASS_SLAYER                                       = 2,
	CLASS_BERSERKER                                    = 3,
	CLASS_SORCERER                                     = 4,
	CLASS_ARCHER                                       = 5,
	CLASS_PRIEST                                       = 6,
	CLASS_ELEMENTALIST                                 = 7,
	CLASS_MAX                                          = 8
};

// Enum S1Game.S1ParentSkeletalMeshComponent.ECustomizeOffsetCriteria
enum ECustomizeOffsetCriteria
{
	COC_NONE                                           = 0,
	COC_TOE                                            = 1,
	COC_PELVIS                                         = 2,
	COC_BOTTOM                                         = 3,
	COC_MAX                                            = 4
};


/*
# ========================================================================================= #
# Classes
# ========================================================================================= #
*/

// Class S1Game.S1Actor
// 0x0000 (0x01C0 - 0x01C0)
class AS1Actor : public AActor
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

UClass* AS1Actor::pClassPointer = NULL;

// Class S1Game.S1AnimNodeBlend
// 0x0077 (0x013C - 0x00C5)
class US1AnimNodeBlend : public UAnimNodeBlendBase
{
public:
	TArray< struct FS1AnimPlayInfo >                   m_AnimSeqList;                                    		// 0x00C8 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	unsigned long                                      m_bNewPlayList : 1;                               		// 0x00D4 (0x0004) [0x0000000000000000] [0x00000001] 
	unsigned long                                      m_bCancel : 1;                                    		// 0x00D4 (0x0004) [0x0000000000000000] [0x00000002] 
	unsigned long                                      m_bPendingPlay : 1;                               		// 0x00D4 (0x0004) [0x0000000000000000] [0x00000004] 
	unsigned long                                      m_bSetPosition : 1;                               		// 0x00D4 (0x0004) [0x0000000000000000] [0x00000008] 
	unsigned long                                      m_bFixedBlendInTime : 1;                          		// 0x00D4 (0x0004) [0x0000000000000000] [0x00000010] 
	unsigned long                                      bIsPlayingCustomAnim : 1;                         		// 0x00D4 (0x0004) [0x0000000000000002] [0x00000020] ( CPF_Const )
	float                                              m_fPosition;                                      		// 0x00D8 (0x0004) [0x0000000000000000]              
	float                                              m_fDefaultAnimBlendInTime;                        		// 0x00DC (0x0004) [0x0000000000000000]              
	float                                              m_fRootMotionDistance;                            		// 0x00E0 (0x0004) [0x0000000000000000]              
	int                                                m_CurrentCustomNodeIndex;                         		// 0x00E4 (0x0004) [0x0000000000000000]              
	struct FS1AnimPlayInfo                             m_CurAnimPlayInfo;                                		// 0x00E8 (0x0034) [0x0000000000000000]              
	TArray< struct FPointer >                          m_AnimEventList;                                  		// 0x011C (0x000C) [0x0000000000103002]              ( CPF_Const | CPF_Native | CPF_Transient )
	int                                                TargetChildIndex;                                 		// 0x0128 (0x0004) [0x0000000000000002]              ( CPF_Const )
	TArray< float >                                    TargetWeight;                                     		// 0x012C (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	float                                              BlendTimeToGo;                                    		// 0x0138 (0x0004) [0x0000000000000002]              ( CPF_Const )

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

UClass* US1AnimNodeBlend::pClassPointer = NULL;

// Class S1Game.S1AnimNodeSequence
// 0x0012 (0x0114 - 0x0102)
class US1AnimNodeSequence : public UAnimNodeSequence
{
public:
	TArray< class UAnimSequence* >                     m_AnimSeqArray;                                   		// 0x0104 (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	unsigned long                                      m_bUpdateCurrentTime : 1;                         		// 0x0110 (0x0004) [0x0000000000000000] [0x00000001] 

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

	void SetAnim ( struct FName Sequence );
};

UClass* US1AnimNodeSequence::pClassPointer = NULL;

// Class S1Game.S1AnimNodeSpeedRate
// 0x000F (0x00D4 - 0x00C5)
class US1AnimNodeSpeedRate : public UAnimNodeBlendBase
{
public:
	float                                              BaseRunSpeed;                                     		// 0x00C8 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	float                                              BaseUnarmedRunSpeed;                              		// 0x00CC (0x0004) [0x0000000000002000]              ( CPF_Transient )
	float                                              BaseWalkSpeed;                                    		// 0x00D0 (0x0004) [0x0000000000002000]              ( CPF_Transient )

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

UClass* US1AnimNodeSpeedRate::pClassPointer = NULL;

// Class S1Game.S1AnimNotifyEffect
// 0x0050 (0x008C - 0x003C)
class US1AnimNotifyEffect : public UAnimNotify
{
public:
	struct FString                                     ResourceName;                                     		// 0x003C (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	struct FName                                       BoneName;                                         		// 0x0048 (0x0008) [0x0000000000002000]              ( CPF_Transient )
	struct FVector                                     OffsetLoc;                                        		// 0x0050 (0x000C) [0x0000000000002000]              ( CPF_Transient )
	struct FRotator                                    OffsetRot;                                        		// 0x005C (0x000C) [0x0000000000002000]              ( CPF_Transient )
	float                                              Scale;                                            		// 0x0068 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	struct FVector                                     Scale3D;                                          		// 0x006C (0x000C) [0x0000000000002000]              ( CPF_Transient )
	struct FString                                     RescaleMethodStr;                                 		// 0x0078 (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	unsigned long                                      bGround : 1;                                      		// 0x0084 (0x0004) [0x0000000000002000] [0x00000001] ( CPF_Transient )
	unsigned long                                      bAbsoluteOffsetLoc : 1;                           		// 0x0084 (0x0004) [0x0000000000002000] [0x00000002] ( CPF_Transient )
	unsigned long                                      Follow : 1;                                       		// 0x0084 (0x0004) [0x0000000000002000] [0x00000004] ( CPF_Transient )
	unsigned long                                      bRemoveDupEffect : 1;                             		// 0x0084 (0x0004) [0x0000000000002000] [0x00000008] ( CPF_Transient )
	float                                              PlayRate;                                         		// 0x0088 (0x0004) [0x0000000000002000]              ( CPF_Transient )

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

UClass* US1AnimNotifyEffect::pClassPointer = NULL;

// Class S1Game.S1AnimNotifyEnvCaseEffect
// 0x0048 (0x0084 - 0x003C)
class US1AnimNotifyEnvCaseEffect : public UAnimNotify
{
public:
	struct FString                                     ConditionName;                                    		// 0x003C (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	struct FName                                       BoneName;                                         		// 0x0048 (0x0008) [0x0000000000002000]              ( CPF_Transient )
	struct FRotator                                    Rot;                                              		// 0x0050 (0x000C) [0x0000000000002000]              ( CPF_Transient )
	struct FVector                                     Loc;                                              		// 0x005C (0x000C) [0x0000000000002000]              ( CPF_Transient )
	float                                              PlayRate;                                         		// 0x0068 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	float                                              Scale;                                            		// 0x006C (0x0004) [0x0000000000002000]              ( CPF_Transient )
	struct FVector                                     Scale3D;                                          		// 0x0070 (0x000C) [0x0000000000002000]              ( CPF_Transient )
	unsigned long                                      bDetach : 1;                                      		// 0x007C (0x0004) [0x0000000000002000] [0x00000001] ( CPF_Transient )
	unsigned long                                      bInWater : 1;                                     		// 0x007C (0x0004) [0x0000000000002000] [0x00000002] ( CPF_Transient )
	int                                                eRescaleMethod;                                   		// 0x0080 (0x0004) [0x0000000000002000]              ( CPF_Transient )

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

UClass* US1AnimNotifyEnvCaseEffect::pClassPointer = NULL;

// Class S1Game.S1AnimNotifyMaterialParameter
// 0x0014 (0x0050 - 0x003C)
class US1AnimNotifyMaterialParameter : public UAnimNotify
{
public:
	struct FName                                       ParameterName;                                    		// 0x003C (0x0008) [0x0000000000002000]              ( CPF_Transient )
	float                                              StartValue;                                       		// 0x0044 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	float                                              EndValue;                                         		// 0x0048 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	float                                              Duration;                                         		// 0x004C (0x0004) [0x0000000000002000]              ( CPF_Transient )

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

UClass* US1AnimNotifyMaterialParameter::pClassPointer = NULL;

// Class S1Game.S1AnimNotifySound
// 0x0020 (0x005C - 0x003C)
class US1AnimNotifySound : public UAnimNotify
{
public:
	class USoundCue*                                   Cue;                                              		// 0x003C (0x0004) [0x0000000000002000]              ( CPF_Transient )
	int                                                Type;                                             		// 0x0040 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	float                                              VolumeMultiplier;                                 		// 0x0044 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	float                                              RadiusMultiplier;                                 		// 0x0048 (0x0004) [0x0000000000002000]              ( CPF_Transient )
	struct FString                                     CueName;                                          		// 0x004C (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	int                                                ApplyShapeId;                                     		// 0x0058 (0x0004) [0x0000000000002000]              ( CPF_Transient )

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

UClass* US1AnimNotifySound::pClassPointer = NULL;

// Class S1Game.S1AudioFinishDelegate
// 0x0004 (0x0040 - 0x003C)
class US1AudioFinishDelegate : public UObject
{
public:
	struct FPointer                                    Handler;                                          		// 0x003C (0x0004) [0x0000000000003000]              ( CPF_Native | CPF_Transient )

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

	void OnAudioFinished ( class UAudioComponent* AC );
};

UClass* US1AudioFinishDelegate::pClassPointer = NULL;

// Class S1Game.S1ChannelVolume
// 0x000C (0x0208 - 0x01FC)
class AS1ChannelVolume : public AVolume
{
public:
	unsigned char                                      Channel;                                          		// 0x01FC (0x0001) [0x0000000000000001]              ( CPF_Edit )
	unsigned long                                      bIsInnerVolume : 1;                               		// 0x0200 (0x0004) [0x0000000000000001] [0x00000001] ( CPF_Edit )
	int                                                ChannelVolumeId;                                  		// 0x0204 (0x0004) [0x0000000000003000]              ( CPF_Native | CPF_Transient )

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

UClass* AS1ChannelVolume::pClassPointer = NULL;

// Class S1Game.S1CustomizableSkeletalMeshComponent
// 0x001C (0x04CC - 0x04B0)
class US1CustomizableSkeletalMeshComponent : public USkeletalMeshComponent
{
public:
	TArray< struct FMatrix >                           CustomizeSpaceBases;                              		// 0x04B0 (0x000C) [0x0000000000003002]              ( CPF_Const | CPF_Native | CPF_Transient )
	TArray< struct FMatrix >                           OriginalSpaceBases;                               		// 0x04BC (0x000C) [0x0000000000003002]              ( CPF_Const | CPF_Native | CPF_Transient )
	unsigned long                                      m_bUseCustomize : 1;                              		// 0x04C8 (0x0004) [0x0000000000003000] [0x00000001] ( CPF_Native | CPF_Transient )

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

UClass* US1CustomizableSkeletalMeshComponent::pClassPointer = NULL;

// Class S1Game.S1MusicVolume
// 0x0034 (0x0230 - 0x01FC)
class AS1MusicVolume : public AVolume
{
public:
	unsigned char                                      Channel;                                          		// 0x01FC (0x0001) [0x0000000000000001]              ( CPF_Edit )
	float                                              Priority;                                         		// 0x0200 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              VolumeMultiplier;                                 		// 0x0204 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	unsigned long                                      RandomPlay : 1;                                   		// 0x0208 (0x0004) [0x0000000000000001] [0x00000001] ( CPF_Edit )
	float                                              DelayForFirstTrack;                               		// 0x020C (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              DelayBetweenTracks;                               		// 0x0210 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              FadeInTime;                                       		// 0x0214 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              FadeOutTime;                                      		// 0x0218 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	TArray< class USoundCue* >                         MusicList;                                        		// 0x021C (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	struct FName                                       ComponentName;                                    		// 0x0228 (0x0008) [0x0000000000002000]              ( CPF_Transient )

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

UClass* AS1MusicVolume::pClassPointer = NULL;

// Class S1Game.S1DynamicMusicVolume
// 0x0000 (0x0230 - 0x0230)
class AS1DynamicMusicVolume : public AS1MusicVolume
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

UClass* AS1DynamicMusicVolume::pClassPointer = NULL;

// Class S1Game.S1ExportIconCommandlet
// 0x0000 (0x007C - 0x007C)
class US1ExportIconCommandlet : public UCommandlet
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

UClass* US1ExportIconCommandlet::pClassPointer = NULL;

// Class S1Game.S1ExportMapCommandlet
// 0x0000 (0x007C - 0x007C)
class US1ExportMapCommandlet : public UCommandlet
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

UClass* US1ExportMapCommandlet::pClassPointer = NULL;

// Class S1Game.S1ExportTerapediaXmlCommandlet
// 0x0000 (0x007C - 0x007C)
class US1ExportTerapediaXmlCommandlet : public UCommandlet
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

UClass* US1ExportTerapediaXmlCommandlet::pClassPointer = NULL;

// Class S1Game.S1ExtractPackageVersionCommandlet
// 0x0000 (0x007C - 0x007C)
class US1ExtractPackageVersionCommandlet : public UCommandlet
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

UClass* US1ExtractPackageVersionCommandlet::pClassPointer = NULL;

// Class S1Game.S1GameViewportClient
// 0x0000 (0x0104 - 0x0104)
class US1GameViewportClient : public UGFxGameViewportClient
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

	void eventPostRender ( class UCanvas* Canvas );
	void RenderS1UI ( class UCanvas* CanvasObject );
};

UClass* US1GameViewportClient::pClassPointer = NULL;

// Class S1Game.S1GenerateResourceXmlCommandlet
// 0x0000 (0x007C - 0x007C)
class US1GenerateResourceXmlCommandlet : public UCommandlet
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

UClass* US1GenerateResourceXmlCommandlet::pClassPointer = NULL;

// Class S1Game.S1GFxEICallbackHandler
// 0x0000 (0x003C - 0x003C)
class US1GFxEICallbackHandler : public UGFxEICallbackHandler
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

	bool EICallback ( class UGFxMovie* Movie, struct FString Cmd, class UGFxValue* arg );
};

UClass* US1GFxEICallbackHandler::pClassPointer = NULL;

// Class S1Game.S1GFxFSCmdHandler
// 0x0000 (0x003C - 0x003C)
class US1GFxFSCmdHandler : public UGFxFSCmdHandler
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

	bool FSCommand ( class UGFxMovie* Movie, struct FString Cmd, struct FString arg );
};

UClass* US1GFxFSCmdHandler::pClassPointer = NULL;

// Class S1Game.S1GlobalObjectContainer
// 0x000C (0x0048 - 0x003C)
class US1GlobalObjectContainer : public UObject
{
public:
	TArray< class UObject* >                           Objects;                                          		// 0x003C (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )

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

UClass* US1GlobalObjectContainer::pClassPointer = NULL;

// Class S1Game.S1HUD
// 0x0000 (0x0444 - 0x0444)
class AS1HUD : public AHUD
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

	void DrawHUD ( );
	void OutputString ( class UCanvas* CanvasObject );
};

UClass* AS1HUD::pClassPointer = NULL;

// Class S1Game.S1IsolatedSoundVolume
// 0x0004 (0x0200 - 0x01FC)
class AS1IsolatedSoundVolume : public AVolume
{
public:
	int                                                VolumeId;                                         		// 0x01FC (0x0004) [0x0000000000003000]              ( CPF_Native | CPF_Transient )

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

UClass* AS1IsolatedSoundVolume::pClassPointer = NULL;

// Class S1Game.S1LevelStreamingDistance
// 0x0024 (0x00A0 - 0x007C)
class US1LevelStreamingDistance : public ULevelStreaming
{
public:
	float                                              DistanceVisible;                                  		// 0x007C (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              DistanceLoadingStart;                             		// 0x0080 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              DistanceUnload;                                   		// 0x0084 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	int                                                ZoneNumberX;                                      		// 0x0088 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	int                                                ZoneNumberY;                                      		// 0x008C (0x0004) [0x0000000000000001]              ( CPF_Edit )
	struct FVector                                     Origin;                                           		// 0x0090 (0x000C) [0x0000000000000001]              ( CPF_Edit )
	unsigned long                                      m_bShouldBeLoaded : 1;                            		// 0x009C (0x0004) [0x0000000000000000] [0x00000001] 
	unsigned long                                      m_bShouldBeVisible : 1;                           		// 0x009C (0x0004) [0x0000000000000000] [0x00000002] 

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

UClass* US1LevelStreamingDistance::pClassPointer = NULL;

// Class S1Game.S1LevelStreamingBaseLevel
// 0x0000 (0x00A0 - 0x00A0)
class US1LevelStreamingBaseLevel : public US1LevelStreamingDistance
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

UClass* US1LevelStreamingBaseLevel::pClassPointer = NULL;

// Class S1Game.S1LevelStreamingSound
// 0x0000 (0x00A0 - 0x00A0)
class US1LevelStreamingSound : public US1LevelStreamingDistance
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

UClass* US1LevelStreamingSound::pClassPointer = NULL;

// Class S1Game.S1LevelStreamingSuperLow
// 0x0000 (0x00A0 - 0x00A0)
class US1LevelStreamingSuperLow : public US1LevelStreamingDistance
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

UClass* US1LevelStreamingSuperLow::pClassPointer = NULL;

// Class S1Game.S1LevelStreamingVOID
// 0x0000 (0x007C - 0x007C)
class US1LevelStreamingVOID : public ULevelStreaming
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

UClass* US1LevelStreamingVOID::pClassPointer = NULL;

// Class S1Game.S1MatineeActorBase
// 0x04D0 (0x06B0 - 0x01E0)
class AS1MatineeActorBase : public ASkeletalMeshActorMAT
{
public:
	int                                                ShapeTemplateId;                                  		// 0x01E0 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class USkeletalMesh*                               TotalBoneMesh;                                    		// 0x01E4 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	struct FSkelPartData                               BodyPart;                                         		// 0x01E8 (0x003C) [0x0000000000480001]              ( CPF_Edit | CPF_Component | CPF_NeedCtorLink )
	struct FSkelPartData                               HandPart;                                         		// 0x0224 (0x003C) [0x0000000000480001]              ( CPF_Edit | CPF_Component | CPF_NeedCtorLink )
	struct FSkelPartData                               FootPart;                                         		// 0x0260 (0x003C) [0x0000000000480001]              ( CPF_Edit | CPF_Component | CPF_NeedCtorLink )
	struct FSkelPartData                               FacePart;                                         		// 0x029C (0x003C) [0x0000000000480001]              ( CPF_Edit | CPF_Component | CPF_NeedCtorLink )
	struct FSkelPartData                               HairPart;                                         		// 0x02D8 (0x003C) [0x0000000000480001]              ( CPF_Edit | CPF_Component | CPF_NeedCtorLink )
	struct FSkelPartData                               TailPart;                                         		// 0x0314 (0x003C) [0x0000000000480001]              ( CPF_Edit | CPF_Component | CPF_NeedCtorLink )
	struct FStaticPartData                             LWeaponOutPart;                                   		// 0x0350 (0x0034) [0x0000000000080001]              ( CPF_Edit | CPF_Component )
	struct FStaticPartData                             RWeaponOutPart;                                   		// 0x0384 (0x0034) [0x0000000000080001]              ( CPF_Edit | CPF_Component )
	struct FStaticPartData                             LWeaponInPart;                                    		// 0x03B8 (0x0034) [0x0000000000080001]              ( CPF_Edit | CPF_Component )
	struct FStaticPartData                             RWeaponInPart;                                    		// 0x03EC (0x0034) [0x0000000000080001]              ( CPF_Edit | CPF_Component )
	struct FFaceCustomizeData                          FaceCustomData;                                   		// 0x0420 (0x0018) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	struct FBodyCustomizeData                          BodyCustomData;                                   		// 0x0438 (0x0010) [0x0000000000402001]              ( CPF_Edit | CPF_Transient | CPF_NeedCtorLink )
	class UAnimTree*                                   DefaultAnimTree;                                  		// 0x0448 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	TArray< class UAnimSet* >                          BodyAnimSets;                                     		// 0x044C (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	TArray< class UAnimSet* >                          FaceAnimSets;                                     		// 0x0458 (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	TArray< class UAnimSet* >                          HairAnimSets;                                     		// 0x0464 (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	TArray< class UAnimSet* >                          TailAnimSets;                                     		// 0x0470 (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	TArray< class UAnimSet* >                          WeaponAnimSets;                                   		// 0x047C (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	unsigned long                                      bWeaponOut : 1;                                   		// 0x0488 (0x0004) [0x0000000000000001] [0x00000001] ( CPF_Edit )
	unsigned long                                      bWeaponIsSkeletalMesh : 1;                        		// 0x0488 (0x0004) [0x0000000000000001] [0x00000002] ( CPF_Edit )
	unsigned long                                      bForceNoWeapon : 1;                               		// 0x0488 (0x0004) [0x0000000000000001] [0x00000004] ( CPF_Edit )
	unsigned long                                      REFRESH : 1;                                      		// 0x0488 (0x0004) [0x0000000000000001] [0x00000008] ( CPF_Edit )
	unsigned long                                      bNeedUpdate : 1;                                  		// 0x0488 (0x0004) [0x0000000000002000] [0x00000010] ( CPF_Transient )
	struct FLightingChannelContainer                   LightingChannels;                                 		// 0x048C (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class US1ParentSkeletalMeshComponent*              TotalBoneComp;                                    		// 0x0490 (0x0004) [0x0000000004082008]              ( CPF_ExportObject | CPF_Transient | CPF_Component | CPF_EditInline )
	TArray< class UAnimNodeSlot* >                     FaceSlotNodes;                                    		// 0x0494 (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	TArray< class UAnimNodeSlot* >                     HairSlotNodes;                                    		// 0x04A0 (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	TArray< class UAnimNodeSlot* >                     TailSlotNodes;                                    		// 0x04AC (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	TArray< class UAnimNodeSlot* >                     WeaponLSlotNodes;                                 		// 0x04B8 (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	TArray< class UAnimNodeSlot* >                     WeaponRSlotNodes;                                 		// 0x04C4 (0x000C) [0x0000000000402000]              ( CPF_Transient | CPF_NeedCtorLink )
	struct FS1SkelPartData                             AccHairPart;                                      		// 0x04D0 (0x0060) [0x0000000000482000]              ( CPF_Transient | CPF_Component | CPF_NeedCtorLink )
	struct FS1SkelPartData                             AccFacePart;                                      		// 0x0530 (0x0060) [0x0000000000482000]              ( CPF_Transient | CPF_Component | CPF_NeedCtorLink )
	struct FS1SkelPartData                             AccBackPart;                                      		// 0x0590 (0x0060) [0x0000000000482000]              ( CPF_Transient | CPF_Component | CPF_NeedCtorLink )
	struct FS1SkelPartData                             LWeaponOutSkelPart;                               		// 0x05F0 (0x0060) [0x0000000000482000]              ( CPF_Transient | CPF_Component | CPF_NeedCtorLink )
	struct FS1SkelPartData                             RWeaponOutSkelPart;                               		// 0x0650 (0x0060) [0x0000000000482000]              ( CPF_Transient | CPF_Component | CPF_NeedCtorLink )

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

UClass* AS1MatineeActorBase::pClassPointer = NULL;

// Class S1Game.S1MatineeActorPlayer
// 0x0003 (0x06B3 - 0x06B0)
class AS1MatineeActorPlayer : public AS1MatineeActorBase
{
public:
	unsigned char                                      EditorRace;                                       		// 0x06B0 (0x0001) [0x0000000000000001]              ( CPF_Edit )
	unsigned char                                      EditorGender;                                     		// 0x06B1 (0x0001) [0x0000000000000001]              ( CPF_Edit )
	unsigned char                                      EditorClass;                                      		// 0x06B2 (0x0001) [0x0000000000000001]              ( CPF_Edit )

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

UClass* AS1MatineeActorPlayer::pClassPointer = NULL;

// Class S1Game.S1MatineeActorVillager
// 0x0006 (0x06B6 - 0x06B0)
class AS1MatineeActorVillager : public AS1MatineeActorBase
{
public:
	int                                                ShapeId;                                          		// 0x06B0 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	unsigned char                                      Race;                                             		// 0x06B4 (0x0001) [0x0000000000000001]              ( CPF_Edit )
	unsigned char                                      Gender;                                           		// 0x06B5 (0x0001) [0x0000000000000001]              ( CPF_Edit )

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

UClass* AS1MatineeActorVillager::pClassPointer = NULL;

// Class S1Game.S1MinimapVolume
// 0x0008 (0x0204 - 0x01FC)
class AS1MinimapVolume : public AVolume
{
public:
	float                                              Priority;                                         		// 0x01FC (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class UTexture*                                    Texture;                                          		// 0x0200 (0x0004) [0x0000000000000001]              ( CPF_Edit )

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

UClass* AS1MinimapVolume::pClassPointer = NULL;

// Class S1Game.S1PackShadersCommandlet
// 0x0000 (0x007C - 0x007C)
class US1PackShadersCommandlet : public UCommandlet
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

UClass* US1PackShadersCommandlet::pClassPointer = NULL;

// Class S1Game.S1ParentSkeletalMeshComponent
// 0x001D (0x04E9 - 0x04CC)
class US1ParentSkeletalMeshComponent : public US1CustomizableSkeletalMeshComponent
{
public:
	TArray< struct FS1PSMCBone >                       m_PSMCBoneArray;                                  		// 0x04CC (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	TArray< struct FName >                             m_WorkingBoneArray;                               		// 0x04D8 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	unsigned long                                      m_bHaveParts : 1;                                 		// 0x04E4 (0x0004) [0x0000000000000000] [0x00000001] 
	unsigned char                                      m_CustomizeOffsetCriteria;                        		// 0x04E8 (0x0001) [0x0000000000003000]              ( CPF_Native | CPF_Transient )

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

UClass* US1ParentSkeletalMeshComponent::pClassPointer = NULL;

// Class S1Game.S1PhysicalMaterialProperty
// 0x0008 (0x0044 - 0x003C)
class US1PhysicalMaterialProperty : public UPhysicalMaterialPropertyBase
{
public:
	struct FName                                       FootStepType;                                     		// 0x003C (0x0008) [0x0000000000000001]              ( CPF_Edit )

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

UClass* US1PhysicalMaterialProperty::pClassPointer = NULL;

// Class S1Game.S1PlayerCamera
// 0x0000 (0x0360 - 0x0360)
class AS1PlayerCamera : public ACamera
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

	void UpdateViewTarget ( float DeltaTime, struct FTViewTarget* OutVT );
	void ApplyCameraModifiersNative ( float DeltaTime, struct FTPOV* OutPOV );
	void eventApplyCameraModifiers ( float DeltaTime, struct FTPOV* OutPOV );
	void eventPostBeginPlay ( );
};

UClass* AS1PlayerCamera::pClassPointer = NULL;

// Class S1Game.S1PlayerController
// 0x002C (0x05D4 - 0x05A8)
class AS1PlayerController : public APlayerController
{
public:
	float                                              WeaponImpulse;                                    		// 0x05A8 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              HoldDistanceMin;                                  		// 0x05AC (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              HoldDistanceMax;                                  		// 0x05B0 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              ThrowImpulse;                                     		// 0x05B4 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              ChangeHoldDistanceIncrement;                      		// 0x05B8 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class URB_Handle*                                  PhysicsGrabber;                                   		// 0x05BC (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	float                                              HoldDistance;                                     		// 0x05C0 (0x0004) [0x0000000000000000]              
	struct FQuat                                       HoldOrientation;                                  		// 0x05C4 (0x0010) [0x0000000000000000]              

private:
	static UClass* pClassPointer;

public:
	static UClass* StaticClass()
	{
		if ( ! pClassPointer )
			pClassPointer = NULL;

		return pClassPointer;
	};

	void DisplayGameMenu ( );
	void ShowMenu ( );
	void eventPlayerTick ( float DeltaTime );
	void StopAltFire ( unsigned char FireModeNum );
	void StartAltFire ( unsigned char FireModeNum );
	void NextWeapon ( );
	void PrevWeapon ( );
	void UnregisterPlayerDataStores ( );
	void RegisterCustomPlayerDataStores ( );
	void eventPostBeginPlay ( );
};

UClass* AS1PlayerController::pClassPointer = NULL;

// Class S1Game.S1RecacheTerrainCommandlet
// 0x0000 (0x007C - 0x007C)
class US1RecacheTerrainCommandlet : public UCommandlet
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

UClass* US1RecacheTerrainCommandlet::pClassPointer = NULL;

// Class S1Game.S1SceneCaptureReflectActor
// 0x0010 (0x01DC - 0x01CC)
class AS1SceneCaptureReflectActor : public ASceneCaptureReflectActor
{
public:
	TArray< class UObject* >                           CacheObjects;                                     		// 0x01CC (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	unsigned long                                      bIsWideBroadcaster : 1;                           		// 0x01D8 (0x0004) [0x0000000000000000] [0x00000001] 

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

UClass* AS1SceneCaptureReflectActor::pClassPointer = NULL;

// Class S1Game.S1SeqAct_CameraShake
// 0x000C (0x00F4 - 0x00E8)
class US1SeqAct_CameraShake : public USequenceAction
{
public:
	float                                              Duration;                                         		// 0x00E8 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              Power;                                            		// 0x00EC (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              Speed;                                            		// 0x00F0 (0x0004) [0x0000000000000001]              ( CPF_Edit )

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

UClass* US1SeqAct_CameraShake::pClassPointer = NULL;

// Class S1Game.S1SeqAct_ChangeWeapon
// 0x0004 (0x00EC - 0x00E8)
class US1SeqAct_ChangeWeapon : public USequenceAction
{
public:
	class AS1MatineeActorBase*                         Target;                                           		// 0x00E8 (0x0004) [0x0000000000000001]              ( CPF_Edit )

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

UClass* US1SeqAct_ChangeWeapon::pClassPointer = NULL;

// Class S1Game.S1SeqAct_MovieScript
// 0x0010 (0x00F8 - 0x00E8)
class US1SeqAct_MovieScript : public USequenceAction
{
public:
	struct FString                                     MovieScriptId;                                    		// 0x00E8 (0x000C) [0x0000000000400001]              ( CPF_Edit | CPF_NeedCtorLink )
	int                                                SceneId;                                          		// 0x00F4 (0x0004) [0x0000000000000001]              ( CPF_Edit )

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

UClass* US1SeqAct_MovieScript::pClassPointer = NULL;

// Class S1Game.S1SeqAct_ToggleCinematic
// 0x0000 (0x00E8 - 0x00E8)
class US1SeqAct_ToggleCinematic : public USequenceAction
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

UClass* US1SeqAct_ToggleCinematic::pClassPointer = NULL;

// Class S1Game.S1SeqAct_WeaponTrail
// 0x001C (0x0104 - 0x00E8)
class US1SeqAct_WeaponTrail : public USequenceAction
{
public:
	class UParticleSystem*                             WeaponTrailParticle;                              		// 0x00E8 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	struct FName                                       BoneName;                                         		// 0x00EC (0x0008) [0x0000000000000001]              ( CPF_Edit )
	float                                              Position;                                         		// 0x00F4 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	float                                              Length;                                           		// 0x00F8 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	class AActor*                                      Actor;                                            		// 0x00FC (0x0004) [0x0000000000000001]              ( CPF_Edit )
	unsigned long                                      bMatineeChildSlot : 1;                            		// 0x0100 (0x0004) [0x0000000000000001] [0x00000001] ( CPF_Edit )

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

UClass* US1SeqAct_WeaponTrail::pClassPointer = NULL;

// Class S1Game.S1SkelControlFoot
// 0x0044 (0x00D8 - 0x0094)
class US1SkelControlFoot : public USkelControlBase
{
public:
	float                                              LimitHeight;                                      		// 0x0094 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	unsigned char                                      BendAxis;                                         		// 0x0098 (0x0001) [0x0000000000000001]              ( CPF_Edit )
	unsigned long                                      bInvertBendAxis : 1;                              		// 0x009C (0x0004) [0x0000000000000001] [0x00000001] ( CPF_Edit )
	unsigned long                                      bAnimBend : 1;                                    		// 0x009C (0x0004) [0x0000000000000001] [0x00000002] ( CPF_Edit )
	unsigned long                                      bEnableFootUpDir : 1;                             		// 0x009C (0x0004) [0x0000000000000001] [0x00000004] ( CPF_Edit )
	unsigned long                                      bSameFloor : 1;                                   		// 0x009C (0x0004) [0x0000000000000000] [0x00000008] 
	float                                              OwnerMaxHeight;                                   		// 0x00A0 (0x0004) [0x0000000000000001]              ( CPF_Edit )
	struct FVector                                     FootPlacement;                                    		// 0x00A4 (0x000C) [0x0000000000000000]              
	struct FVector                                     DamageMotionTranslation;                          		// 0x00B0 (0x000C) [0x0000000000000000]              
	struct FVector                                     FloorLocation;                                    		// 0x00BC (0x000C) [0x0000000000000000]              
	struct FVector                                     FloorNormal;                                      		// 0x00C8 (0x000C) [0x0000000000000000]              
	float                                              FootHeight;                                       		// 0x00D4 (0x0004) [0x0000000000000000]              

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

UClass* US1SkelControlFoot::pClassPointer = NULL;

// Class S1Game.S1SkelControlWeapon
// 0x001C (0x00B0 - 0x0094)
class US1SkelControlWeapon : public USkelControlBase
{
public:
	TArray< struct FVector >                           vControlledBoneLocation;                          		// 0x0094 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	TArray< int >                                      AffectedBoneIndices;                              		// 0x00A0 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	struct FPointer                                    m_pActiveWeaponIKControlBase;                     		// 0x00AC (0x0004) [0x0000000000001000]              ( CPF_Native )

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

UClass* US1SkelControlWeapon::pClassPointer = NULL;

// Class S1Game.S1SkeletalMeshActor
// 0x0014 (0x01D4 - 0x01C0)
class AS1SkeletalMeshActor : public AActor
{
public:
	class US1ParentSkeletalMeshComponent*              ParentSkeletalMeshComponent;                      		// 0x01C0 (0x0004) [0x0000000004080008]              ( CPF_ExportObject | CPF_Component | CPF_EditInline )
	TArray< class UObject* >                           CacheObjects;                                     		// 0x01C4 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	unsigned long                                      bIsWideBroadcaster : 1;                           		// 0x01D0 (0x0004) [0x0000000000000000] [0x00000001] 

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

UClass* AS1SkeletalMeshActor::pClassPointer = NULL;

// Class S1Game.S1SkeletalMeshActorMAT
// 0x0058 (0x0238 - 0x01E0)
class AS1SkeletalMeshActorMAT : public ASkeletalMeshActorMAT
{
public:
	class US1ParentSkeletalMeshComponent*              TotalBoneMesh;                                    		// 0x01E0 (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	class USkeletalMeshComponent*                      BodyPart;                                         		// 0x01E4 (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	class USkeletalMeshComponent*                      HandPart;                                         		// 0x01E8 (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	class USkeletalMeshComponent*                      LegPart;                                          		// 0x01EC (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	class USkeletalMeshComponent*                      FacePart;                                         		// 0x01F0 (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	struct FName                                       FaceBone;                                         		// 0x01F4 (0x0008) [0x0000000000000001]              ( CPF_Edit )
	class USkeletalMeshComponent*                      HairPart;                                         		// 0x01FC (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	struct FName                                       HairBone;                                         		// 0x0200 (0x0008) [0x0000000000000001]              ( CPF_Edit )
	class UStaticMeshComponent*                        LWeapon;                                          		// 0x0208 (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	struct FName                                       LWeaponBone;                                      		// 0x020C (0x0008) [0x0000000000000001]              ( CPF_Edit )
	class UStaticMeshComponent*                        RWeapon;                                          		// 0x0214 (0x0004) [0x0000000004080009]              ( CPF_Edit | CPF_ExportObject | CPF_Component | CPF_EditInline )
	struct FName                                       RWeaponBone;                                      		// 0x0218 (0x0008) [0x0000000000000001]              ( CPF_Edit )
	TArray< class UAnimNodeSlot* >                     FaceSlotNodes;                                    		// 0x0220 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	TArray< class UAnimNodeSlot* >                     HairSlotNodes;                                    		// 0x022C (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )

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

UClass* AS1SkeletalMeshActorMAT::pClassPointer = NULL;

// Class S1Game.S1SmallClientCommandlet
// 0x0000 (0x007C - 0x007C)
class US1SmallClientCommandlet : public UCommandlet
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

UClass* US1SmallClientCommandlet::pClassPointer = NULL;

// Class S1Game.S1StaticMeshActor
// 0x0010 (0x01E0 - 0x01D0)
class AS1StaticMeshActor : public AStaticMeshActor
{
public:
	TArray< class UObject* >                           CacheObjects;                                     		// 0x01D0 (0x000C) [0x0000000000400000]              ( CPF_NeedCtorLink )
	unsigned long                                      bIsWideBroadcaster : 1;                           		// 0x01DC (0x0004) [0x0000000000000000] [0x00000001] 

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

UClass* AS1StaticMeshActor::pClassPointer = NULL;

// Class S1Game.S1Validate2Commandlet
// 0x0000 (0x007C - 0x007C)
class US1Validate2Commandlet : public UCommandlet
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

UClass* US1Validate2Commandlet::pClassPointer = NULL;

// Class S1Game.S1ValidateCommandlet
// 0x0000 (0x007C - 0x007C)
class US1ValidateCommandlet : public UCommandlet
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

UClass* US1ValidateCommandlet::pClassPointer = NULL;

// Class S1Game.S1WaterVolume
// 0x0000 (0x01FC - 0x01FC)
class AS1WaterVolume : public AVolume
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

UClass* AS1WaterVolume::pClassPointer = NULL;

// Class S1Game.ActorFactoryS1MatineeActorPlayer
// 0x0000 (0x0074 - 0x0074)
class UActorFactoryS1MatineeActorPlayer : public UActorFactorySkeletalMesh
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

UClass* UActorFactoryS1MatineeActorPlayer::pClassPointer = NULL;

// Class S1Game.ActorFactoryS1MatineeActorVillager
// 0x0000 (0x0074 - 0x0074)
class UActorFactoryS1MatineeActorVillager : public UActorFactorySkeletalMesh
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

UClass* UActorFactoryS1MatineeActorVillager::pClassPointer = NULL;

// Class S1Game.ActorFactoryS1SkeletalMeshMAT
// 0x0000 (0x0074 - 0x0074)
class UActorFactoryS1SkeletalMeshMAT : public UActorFactorySkeletalMesh
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

UClass* UActorFactoryS1SkeletalMeshMAT::pClassPointer = NULL;

// Class S1Game.S1GameInfo
// 0x0000 (0x03A8 - 0x03A8)
class AS1GameInfo : public AGameInfo
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

	class APlayerController* eventLogin ( struct FString Portal, struct FString Options, struct FString* ErrorMessage );
};

UClass* AS1GameInfo::pClassPointer = NULL;

// Class S1Game.S1SoundNodeSequence
// 0x0000 (0x0058 - 0x0058)
class US1SoundNodeSequence : public USoundNodeConcatenator
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

UClass* US1SoundNodeSequence::pClassPointer = NULL;


#ifdef _MSC_VER
	#pragma pack ( pop )
#endif