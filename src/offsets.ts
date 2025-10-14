import { isAndroid } from "./platform";

export const Offsets = {
    ServerConnectionUpdate: isAndroid ? 0x45fa98 : 0x1fa618,
    HasConnectFailed: Process.pointerSize,
    State: isAndroid ? 16 : 24,
    GetMessageType: Process.pointerSize * 5,
    Destruct: Process.pointerSize * 7,
    Encode: 2 * Process.pointerSize,
    Decode: 3 * Process.pointerSize,
    MessageManagerReceiveMessageThunk: 0x1f0c44,
    MessageManagerReceiveMessage: isAndroid ? 0x45318c : 0x1f0c48,
    HomePageStartGame: isAndroid ? 0x58aba8 : 0x2e18c4,
    MessagingSend: isAndroid ? 0x9b05fc : 0xdbdc40,
    MessageManagerSendMessage: isAndroid ? 0x452fd0 : 0x1f0b98,
    NativeFontFormatString: 0x0, // todo
    MessageManagerInstance: isAndroid ? 0xda52e4 : 0x11828d8,
    CreateMessageByType: isAndroid ? 0x6f1b90 : 0x3ecd4c,
    LogicLaserMessageFactory: isAndroid ? 0xce0a9a : 0x101891e,
    IsAuthenticated: isAndroid ? 0x9b05e4 : 0xdbdc2c,

    Version: isAndroid ? 84 : 136,
    ByteStream: Process.pointerSize,
    PayloadOffset: isAndroid ? 16 : 20,
    PayloadSize: isAndroid ? 20 : 24,
    PayloadPtr: isAndroid ? 44 : 56,

    OperatorNew: isAndroid ? 0xcb6380 : 0xe0095c,
    StringConstructor: isAndroid ? 0x9c428c : 0xdcfacc,
    IsDev: isAndroid ? 0x5ecbc8 : 0x32fbe8,
    IsDeveloperBuild: isAndroid ? 0x5ecc0c : 0x32fc24,
    IsProd: isAndroid ? 0x5ecbd0 : 0x32fbf4,

    DebuggerError: isAndroid ? 0x813fa0 : 0xc0191c,
    StringTableGetString: isAndroid ? 0x5d4eb8 : 0x31cfc8,
    MoieClipGetTextFieldByName: isAndroid ? 0x7d0ce4 : 0xbc4f04,
    TextFieldSetText: isAndroid ? 0x7ff96c : 0x11b4d94,
    MovieClipGetMovieClipByName: isAndroid ? 0x7d0920 : 0xbc4bf0,
    GameButtonConstructor: isAndroid ? 0x2a5410 : 0x0,
    ResourceManagerGetMovieClip: isAndroid ? 0x7a28e4 : 0xb88b54,
    CustomButtonSetMovieClip: isAndroid ? 0x803ba0 : 0x0,
    CustomButtonSetButtonListener: isAndroid ? 0x803ce8 : 0x0,
    MovieClipHelperSetTextAndScaleIfNecassery: isAndroid ? 0x0 : 0x326e7c,
    MovieClipSetChildVisible: isAndroid ? 0x0 : 0xbc543c,
    ScreenGetWidth: isAndroid ? 0x0 : 0xde009c,
    ScreenGetHeight: isAndroid ? 0x0 : 0xde00a8,
    GUIShowFloaterTextAtDefaultPos: isAndroid ? 0x0 : 0x99160,
    GUIInstance: isAndroid ? 0x0 : 0x11827d0,

    SettingsGetSelectedLanguage: isAndroid ? 0x0 : 0xda44,
    LogicVersionIsChinaVersion: isAndroid ? 0x0 : 0x31d710,

    Messaging: isAndroid ? 9 * Process.pointerSize : 72,

    TutorialThingy: isAndroid ? 0x0 : 0x2f1cc0,

    MessageManagerSendKeepAliveMessage: isAndroid ? 0x0 : 0x1f6f34
};