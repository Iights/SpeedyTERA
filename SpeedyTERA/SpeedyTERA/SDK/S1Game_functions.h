#ifdef _MSC_VER
	#pragma pack ( push, 0x4 )
#endif

/*
# ========================================================================================= #
# Functions
# ========================================================================================= #
*/

// Function S1Game.S1AnimNodeSequence.SetAnim
// [0x00020400] ( FUNC_Native )
// Parameters infos:
// struct FName                   Sequence                       ( CPF_Parm )

void US1AnimNodeSequence::SetAnim ( struct FName Sequence )
{
	static UFunction* pFnSetAnim = NULL;

	if ( ! pFnSetAnim )
		pFnSetAnim = NULL;

	US1AnimNodeSequence_execSetAnim_Parms SetAnim_Parms;
	memcpy ( &SetAnim_Parms.Sequence, &Sequence, 0x8 );

	pFnSetAnim->FunctionFlags |= ~0x400;

	this->ProcessEvent ( pFnSetAnim, &SetAnim_Parms, NULL );

	pFnSetAnim->FunctionFlags |= 0x400;
};

// Function S1Game.S1AudioFinishDelegate.OnAudioFinished
// [0x00020400] ( FUNC_Native )
// Parameters infos:
// class UAudioComponent*         AC                             ( CPF_Parm | CPF_EditInline )

void US1AudioFinishDelegate::OnAudioFinished ( class UAudioComponent* AC )
{
	static UFunction* pFnOnAudioFinished = NULL;

	if ( ! pFnOnAudioFinished )
		pFnOnAudioFinished = NULL;

	US1AudioFinishDelegate_execOnAudioFinished_Parms OnAudioFinished_Parms;
	OnAudioFinished_Parms.AC = AC;

	pFnOnAudioFinished->FunctionFlags |= ~0x400;

	this->ProcessEvent ( pFnOnAudioFinished, &OnAudioFinished_Parms, NULL );

	pFnOnAudioFinished->FunctionFlags |= 0x400;
};

// Function S1Game.S1GameViewportClient.PostRender
// [0x00020802] ( FUNC_Event )
// Parameters infos:
// class UCanvas*                 Canvas                         ( CPF_Parm )

void US1GameViewportClient::eventPostRender ( class UCanvas* Canvas )
{
	static UFunction* pFnPostRender = NULL;

	if ( ! pFnPostRender )
		pFnPostRender = NULL;

	US1GameViewportClient_eventPostRender_Parms PostRender_Parms;
	PostRender_Parms.Canvas = Canvas;

	this->ProcessEvent ( pFnPostRender, &PostRender_Parms, NULL );
};

// Function S1Game.S1GameViewportClient.RenderS1UI
// [0x00020400] ( FUNC_Native )
// Parameters infos:
// class UCanvas*                 CanvasObject                   ( CPF_Parm )

void US1GameViewportClient::RenderS1UI ( class UCanvas* CanvasObject )
{
	static UFunction* pFnRenderS1UI = NULL;

	if ( ! pFnRenderS1UI )
		pFnRenderS1UI = NULL;

	US1GameViewportClient_execRenderS1UI_Parms RenderS1UI_Parms;
	RenderS1UI_Parms.CanvasObject = CanvasObject;

	pFnRenderS1UI->FunctionFlags |= ~0x400;

	this->ProcessEvent ( pFnRenderS1UI, &RenderS1UI_Parms, NULL );

	pFnRenderS1UI->FunctionFlags |= 0x400;
};

// Function S1Game.S1GFxEICallbackHandler.EICallback
// [0x00020400] ( FUNC_Native )
// Parameters infos:
// bool                           ReturnValue                    ( CPF_Parm | CPF_OutParm | CPF_ReturnParm )
// class UGFxMovie*               Movie                          ( CPF_Parm )
// struct FString                 Cmd                            ( CPF_Parm | CPF_NeedCtorLink )
// class UGFxValue*               arg                            ( CPF_Parm )

bool US1GFxEICallbackHandler::EICallback ( class UGFxMovie* Movie, struct FString Cmd, class UGFxValue* arg )
{
	static UFunction* pFnEICallback = NULL;

	if ( ! pFnEICallback )
		pFnEICallback = NULL;

	US1GFxEICallbackHandler_execEICallback_Parms EICallback_Parms;
	EICallback_Parms.Movie = Movie;
	memcpy ( &EICallback_Parms.Cmd, &Cmd, 0xC );
	EICallback_Parms.arg = arg;

	pFnEICallback->FunctionFlags |= ~0x400;

	this->ProcessEvent ( pFnEICallback, &EICallback_Parms, NULL );

	pFnEICallback->FunctionFlags |= 0x400;

	return EICallback_Parms.ReturnValue;
};

// Function S1Game.S1GFxFSCmdHandler.FSCommand
// [0x00020400] ( FUNC_Native )
// Parameters infos:
// bool                           ReturnValue                    ( CPF_Parm | CPF_OutParm | CPF_ReturnParm )
// class UGFxMovie*               Movie                          ( CPF_Parm )
// struct FString                 Cmd                            ( CPF_Parm | CPF_NeedCtorLink )
// struct FString                 arg                            ( CPF_Parm | CPF_NeedCtorLink )

bool US1GFxFSCmdHandler::FSCommand ( class UGFxMovie* Movie, struct FString Cmd, struct FString arg )
{
	static UFunction* pFnFSCommand = NULL;

	if ( ! pFnFSCommand )
		pFnFSCommand = NULL;

	US1GFxFSCmdHandler_execFSCommand_Parms FSCommand_Parms;
	FSCommand_Parms.Movie = Movie;
	memcpy ( &FSCommand_Parms.Cmd, &Cmd, 0xC );
	memcpy ( &FSCommand_Parms.arg, &arg, 0xC );

	pFnFSCommand->FunctionFlags |= ~0x400;

	this->ProcessEvent ( pFnFSCommand, &FSCommand_Parms, NULL );

	pFnFSCommand->FunctionFlags |= 0x400;

	return FSCommand_Parms.ReturnValue;
};

// Function S1Game.S1HUD.DrawHUD
// [0x00020002] 
// Parameters infos:

void AS1HUD::DrawHUD ( )
{
	static UFunction* pFnDrawHUD = NULL;

	if ( ! pFnDrawHUD )
		pFnDrawHUD = NULL;

	AS1HUD_execDrawHUD_Parms DrawHUD_Parms;

	this->ProcessEvent ( pFnDrawHUD, &DrawHUD_Parms, NULL );
};

// Function S1Game.S1HUD.OutputString
// [0x00020400] ( FUNC_Native )
// Parameters infos:
// class UCanvas*                 CanvasObject                   ( CPF_Parm )

void AS1HUD::OutputString ( class UCanvas* CanvasObject )
{
	static UFunction* pFnOutputString = NULL;

	if ( ! pFnOutputString )
		pFnOutputString = NULL;

	AS1HUD_execOutputString_Parms OutputString_Parms;
	OutputString_Parms.CanvasObject = CanvasObject;

	pFnOutputString->FunctionFlags |= ~0x400;

	this->ProcessEvent ( pFnOutputString, &OutputString_Parms, NULL );

	pFnOutputString->FunctionFlags |= 0x400;
};

// Function S1Game.S1PlayerCamera.UpdateViewTarget
// [0x00420002] 
// Parameters infos:
// float                          DeltaTime                      ( CPF_Parm )
// struct FTViewTarget            OutVT                          ( CPF_Parm | CPF_OutParm )

void AS1PlayerCamera::UpdateViewTarget ( float DeltaTime, struct FTViewTarget* OutVT )
{
	static UFunction* pFnUpdateViewTarget = NULL;

	if ( ! pFnUpdateViewTarget )
		pFnUpdateViewTarget = NULL;

	AS1PlayerCamera_execUpdateViewTarget_Parms UpdateViewTarget_Parms;
	UpdateViewTarget_Parms.DeltaTime = DeltaTime;

	this->ProcessEvent ( pFnUpdateViewTarget, &UpdateViewTarget_Parms, NULL );

	if ( OutVT )
		memcpy ( OutVT, &UpdateViewTarget_Parms.OutVT, 0x2C );
};

// Function S1Game.S1PlayerCamera.ApplyCameraModifiersNative
// [0x00440501] ( FUNC_Final | FUNC_Native )
// Parameters infos:
// float                          DeltaTime                      ( CPF_Parm )
// struct FTPOV                   OutPOV                         ( CPF_Parm | CPF_OutParm )

void AS1PlayerCamera::ApplyCameraModifiersNative ( float DeltaTime, struct FTPOV* OutPOV )
{
	static UFunction* pFnApplyCameraModifiersNative = NULL;

	if ( ! pFnApplyCameraModifiersNative )
		pFnApplyCameraModifiersNative = NULL;

	AS1PlayerCamera_execApplyCameraModifiersNative_Parms ApplyCameraModifiersNative_Parms;
	ApplyCameraModifiersNative_Parms.DeltaTime = DeltaTime;

	pFnApplyCameraModifiersNative->FunctionFlags |= ~0x400;

	this->ProcessEvent ( pFnApplyCameraModifiersNative, &ApplyCameraModifiersNative_Parms, NULL );

	pFnApplyCameraModifiersNative->FunctionFlags |= 0x400;

	if ( OutPOV )
		memcpy ( OutPOV, &ApplyCameraModifiersNative_Parms.OutPOV, 0x1C );
};

// Function S1Game.S1PlayerCamera.ApplyCameraModifiers
// [0x00420802] ( FUNC_Event )
// Parameters infos:
// float                          DeltaTime                      ( CPF_Parm )
// struct FTPOV                   OutPOV                         ( CPF_Parm | CPF_OutParm )

void AS1PlayerCamera::eventApplyCameraModifiers ( float DeltaTime, struct FTPOV* OutPOV )
{
	static UFunction* pFnApplyCameraModifiers = NULL;

	if ( ! pFnApplyCameraModifiers )
		pFnApplyCameraModifiers = NULL;

	AS1PlayerCamera_eventApplyCameraModifiers_Parms ApplyCameraModifiers_Parms;
	ApplyCameraModifiers_Parms.DeltaTime = DeltaTime;

	this->ProcessEvent ( pFnApplyCameraModifiers, &ApplyCameraModifiers_Parms, NULL );

	if ( OutPOV )
		memcpy ( OutPOV, &ApplyCameraModifiers_Parms.OutPOV, 0x1C );
};

// Function S1Game.S1PlayerCamera.PostBeginPlay
// [0x00020802] ( FUNC_Event )
// Parameters infos:

void AS1PlayerCamera::eventPostBeginPlay ( )
{
	static UFunction* pFnPostBeginPlay = NULL;

	if ( ! pFnPostBeginPlay )
		pFnPostBeginPlay = NULL;

	AS1PlayerCamera_eventPostBeginPlay_Parms PostBeginPlay_Parms;

	this->ProcessEvent ( pFnPostBeginPlay, &PostBeginPlay_Parms, NULL );
};

// Function S1Game.S1PlayerController.DisplayGameMenu
// [0x00020002] 
// Parameters infos:

void AS1PlayerController::DisplayGameMenu ( )
{
	static UFunction* pFnDisplayGameMenu = NULL;

	if ( ! pFnDisplayGameMenu )
		pFnDisplayGameMenu = NULL;

	AS1PlayerController_execDisplayGameMenu_Parms DisplayGameMenu_Parms;

	this->ProcessEvent ( pFnDisplayGameMenu, &DisplayGameMenu_Parms, NULL );
};

// Function S1Game.S1PlayerController.ShowMenu
// [0x00020202] ( FUNC_Exec )
// Parameters infos:

void AS1PlayerController::ShowMenu ( )
{
	static UFunction* pFnShowMenu = NULL;

	if ( ! pFnShowMenu )
		pFnShowMenu = NULL;

	AS1PlayerController_execShowMenu_Parms ShowMenu_Parms;

	this->ProcessEvent ( pFnShowMenu, &ShowMenu_Parms, NULL );
};

// Function S1Game.S1PlayerController.PlayerTick
// [0x00820802] ( FUNC_Event )
// Parameters infos:
// float                          DeltaTime                      ( CPF_Parm )

void AS1PlayerController::eventPlayerTick ( float DeltaTime )
{
	static UFunction* pFnPlayerTick = NULL;

	if ( ! pFnPlayerTick )
		pFnPlayerTick = NULL;

	AS1PlayerController_eventPlayerTick_Parms PlayerTick_Parms;
	PlayerTick_Parms.DeltaTime = DeltaTime;

	this->ProcessEvent ( pFnPlayerTick, &PlayerTick_Parms, NULL );
};

// Function S1Game.S1PlayerController.StopAltFire
// [0x00024202] ( FUNC_Exec )
// Parameters infos:
// unsigned char                  FireModeNum                    ( CPF_OptionalParm | CPF_Parm )

void AS1PlayerController::StopAltFire ( unsigned char FireModeNum )
{
	static UFunction* pFnStopAltFire = NULL;

	if ( ! pFnStopAltFire )
		pFnStopAltFire = NULL;

	AS1PlayerController_execStopAltFire_Parms StopAltFire_Parms;
	StopAltFire_Parms.FireModeNum = FireModeNum;

	this->ProcessEvent ( pFnStopAltFire, &StopAltFire_Parms, NULL );
};

// Function S1Game.S1PlayerController.StartAltFire
// [0x00824202] ( FUNC_Exec )
// Parameters infos:
// unsigned char                  FireModeNum                    ( CPF_OptionalParm | CPF_Parm )

void AS1PlayerController::StartAltFire ( unsigned char FireModeNum )
{
	static UFunction* pFnStartAltFire = NULL;

	if ( ! pFnStartAltFire )
		pFnStartAltFire = NULL;

	AS1PlayerController_execStartAltFire_Parms StartAltFire_Parms;
	StartAltFire_Parms.FireModeNum = FireModeNum;

	this->ProcessEvent ( pFnStartAltFire, &StartAltFire_Parms, NULL );
};

// Function S1Game.S1PlayerController.NextWeapon
// [0x00020202] ( FUNC_Exec )
// Parameters infos:

void AS1PlayerController::NextWeapon ( )
{
	static UFunction* pFnNextWeapon = NULL;

	if ( ! pFnNextWeapon )
		pFnNextWeapon = NULL;

	AS1PlayerController_execNextWeapon_Parms NextWeapon_Parms;

	this->ProcessEvent ( pFnNextWeapon, &NextWeapon_Parms, NULL );
};

// Function S1Game.S1PlayerController.PrevWeapon
// [0x00020202] ( FUNC_Exec )
// Parameters infos:

void AS1PlayerController::PrevWeapon ( )
{
	static UFunction* pFnPrevWeapon = NULL;

	if ( ! pFnPrevWeapon )
		pFnPrevWeapon = NULL;

	AS1PlayerController_execPrevWeapon_Parms PrevWeapon_Parms;

	this->ProcessEvent ( pFnPrevWeapon, &PrevWeapon_Parms, NULL );
};

// Function S1Game.S1PlayerController.UnregisterPlayerDataStores
// [0x00020102] 
// Parameters infos:

void AS1PlayerController::UnregisterPlayerDataStores ( )
{
	static UFunction* pFnUnregisterPlayerDataStores = NULL;

	if ( ! pFnUnregisterPlayerDataStores )
		pFnUnregisterPlayerDataStores = NULL;

	AS1PlayerController_execUnregisterPlayerDataStores_Parms UnregisterPlayerDataStores_Parms;

	this->ProcessEvent ( pFnUnregisterPlayerDataStores, &UnregisterPlayerDataStores_Parms, NULL );
};

// Function S1Game.S1PlayerController.RegisterCustomPlayerDataStores
// [0x00080102] 
// Parameters infos:

void AS1PlayerController::RegisterCustomPlayerDataStores ( )
{
	static UFunction* pFnRegisterCustomPlayerDataStores = NULL;

	if ( ! pFnRegisterCustomPlayerDataStores )
		pFnRegisterCustomPlayerDataStores = NULL;

	AS1PlayerController_execRegisterCustomPlayerDataStores_Parms RegisterCustomPlayerDataStores_Parms;

	this->ProcessEvent ( pFnRegisterCustomPlayerDataStores, &RegisterCustomPlayerDataStores_Parms, NULL );
};

// Function S1Game.S1PlayerController.PostBeginPlay
// [0x00020902] ( FUNC_Event )
// Parameters infos:

void AS1PlayerController::eventPostBeginPlay ( )
{
	static UFunction* pFnPostBeginPlay = NULL;

	if ( ! pFnPostBeginPlay )
		pFnPostBeginPlay = NULL;

	AS1PlayerController_eventPostBeginPlay_Parms PostBeginPlay_Parms;

	this->ProcessEvent ( pFnPostBeginPlay, &PostBeginPlay_Parms, NULL );
};

// Function S1Game.S1GameInfo.Login
// [0x00C20802] ( FUNC_Event )
// Parameters infos:
// class APlayerController*       ReturnValue                    ( CPF_Parm | CPF_OutParm | CPF_ReturnParm )
// struct FString                 Portal                         ( CPF_Parm | CPF_NeedCtorLink )
// struct FString                 Options                        ( CPF_Parm | CPF_NeedCtorLink )
// struct FString                 ErrorMessage                   ( CPF_Parm | CPF_OutParm | CPF_NeedCtorLink )

class APlayerController* AS1GameInfo::eventLogin ( struct FString Portal, struct FString Options, struct FString* ErrorMessage )
{
	static UFunction* pFnLogin = NULL;

	if ( ! pFnLogin )
		pFnLogin = NULL;

	AS1GameInfo_eventLogin_Parms Login_Parms;
	memcpy ( &Login_Parms.Portal, &Portal, 0xC );
	memcpy ( &Login_Parms.Options, &Options, 0xC );

	this->ProcessEvent ( pFnLogin, &Login_Parms, NULL );

	if ( ErrorMessage )
		memcpy ( ErrorMessage, &Login_Parms.ErrorMessage, 0xC );

	return Login_Parms.ReturnValue;
};


#ifdef _MSC_VER
	#pragma pack ( pop )
#endif