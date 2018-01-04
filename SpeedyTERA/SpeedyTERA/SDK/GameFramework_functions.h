#ifdef _MSC_VER
	#pragma pack ( push, 0x4 )
#endif

/*
# ========================================================================================= #
# Functions
# ========================================================================================= #
*/

// Function GameFramework.GameHUD.StopDrawingChapterTitle
// [0x00020102] 
// Parameters infos:

void AGameHUD::StopDrawingChapterTitle ( )
{
	static UFunction* pFnStopDrawingChapterTitle = NULL;

	if ( ! pFnStopDrawingChapterTitle )
		pFnStopDrawingChapterTitle = NULL;

	AGameHUD_execStopDrawingChapterTitle_Parms StopDrawingChapterTitle_Parms;

	this->ProcessEvent ( pFnStopDrawingChapterTitle, &StopDrawingChapterTitle_Parms, NULL );
};

// Function GameFramework.GameHUD.StartDrawingChapterTitle
// [0x00020102] 
// Parameters infos:
// struct FString                 ChapterName                    ( CPF_Parm | CPF_NeedCtorLink )
// struct FString                 ActName                        ( CPF_Parm | CPF_NeedCtorLink )
// float                          TotalDrawTime                  ( CPF_Parm )
// float                          TotalFadeTime                  ( CPF_Parm )

void AGameHUD::StartDrawingChapterTitle ( struct FString ChapterName, struct FString ActName, float TotalDrawTime, float TotalFadeTime )
{
	static UFunction* pFnStartDrawingChapterTitle = NULL;

	if ( ! pFnStartDrawingChapterTitle )
		pFnStartDrawingChapterTitle = NULL;

	AGameHUD_execStartDrawingChapterTitle_Parms StartDrawingChapterTitle_Parms;
	memcpy ( &StartDrawingChapterTitle_Parms.ChapterName, &ChapterName, 0xC );
	memcpy ( &StartDrawingChapterTitle_Parms.ActName, &ActName, 0xC );
	StartDrawingChapterTitle_Parms.TotalDrawTime = TotalDrawTime;
	StartDrawingChapterTitle_Parms.TotalFadeTime = TotalFadeTime;

	this->ProcessEvent ( pFnStartDrawingChapterTitle, &StartDrawingChapterTitle_Parms, NULL );
};

// Function GameFramework.GameHUD.SetHUDDrawColor
// [0x00024002] 
// Parameters infos:
// unsigned char                  eColor                         ( CPF_Parm )
// unsigned char                  Alpha                          ( CPF_OptionalParm | CPF_Parm )

void AGameHUD::SetHUDDrawColor ( unsigned char eColor, unsigned char Alpha )
{
	static UFunction* pFnSetHUDDrawColor = NULL;

	if ( ! pFnSetHUDDrawColor )
		pFnSetHUDDrawColor = NULL;

	AGameHUD_execSetHUDDrawColor_Parms SetHUDDrawColor_Parms;
	SetHUDDrawColor_Parms.eColor = eColor;
	SetHUDDrawColor_Parms.Alpha = Alpha;

	this->ProcessEvent ( pFnSetHUDDrawColor, &SetHUDDrawColor_Parms, NULL );
};

// Function GameFramework.GamePawn.GetTargetFrictionCylinder
// [0x00420102] 
// Parameters infos:
// float                          CylinderRadius                 ( CPF_Parm | CPF_OutParm )
// float                          CylinderHeight                 ( CPF_Parm | CPF_OutParm )

void AGamePawn::GetTargetFrictionCylinder ( float* CylinderRadius, float* CylinderHeight )
{
	static UFunction* pFnGetTargetFrictionCylinder = NULL;

	if ( ! pFnGetTargetFrictionCylinder )
		pFnGetTargetFrictionCylinder = NULL;

	AGamePawn_execGetTargetFrictionCylinder_Parms GetTargetFrictionCylinder_Parms;

	this->ProcessEvent ( pFnGetTargetFrictionCylinder, &GetTargetFrictionCylinder_Parms, NULL );

	if ( CylinderRadius )
		*CylinderRadius = GetTargetFrictionCylinder_Parms.CylinderRadius;

	if ( CylinderHeight )
		*CylinderHeight = GetTargetFrictionCylinder_Parms.CylinderHeight;
};


#ifdef _MSC_VER
	#pragma pack ( pop )
#endif