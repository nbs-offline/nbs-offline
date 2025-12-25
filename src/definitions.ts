import { Config, readConfig, tryLoadDefaultConfig } from "./config.js";
import { getOffsetsFromJSON, Offsets } from "./offsets.js";
import { isAndroid } from "./platform.js";
import { Player } from "./player.js";
import { getDocumentsDirectory, getPackageName } from "./util.js";

export let base = NULL;

export const libc = isAndroid
  ? Process.getModuleByName("libc.so")
  : Process.getModuleByName("libSystem.B.dylib");

export const malloc = new NativeFunction(
  libc.getExportByName("malloc"),
  "pointer",
  ["uint"],
);

export let player = new Player();
export let documentsDirectory: string;
export let configPath: string;
export let config: Config;
export let pkgName: string;
export let botNames: string[];
export let version: number;

export let createMessageByType: any;
export let operator_new: any;
export let messageManagerReceiveMessage: any;
export let stringCtor: any;
export let messagingSend: any;
export let setTextAndScaleIfNecessary: any;
export let getString: any;
export let setText: any;
export let getMovieClip: any;
export let gameButtonConstructor: any;
export let addChild: any;
export let gotoAndStop: any;
export let getTextFieldByName: any;

export let getX: any;
export let setX: any;
export let getY: any;
export let setY: any;
export let setXY: any;
export let getWidth: any;
export let setWidth: any;
export let getHeight: any;
export let setHeight: any;
export let setMultiline: any;
export let autoAdjustText: any;
export let setScaleX: any;
export let setScaleY: any;
export let getFontSize: any;
export let setFontSize: any;
export let loadAsset: any;
export let setVerticallyCentered: any;
export let showFloaterText: any;

export type ButtonHandler = (ptr: NativePointer) => void;
export const buttonHandlers: Array<{
  ptr: NativePointer;
  handler: ButtonHandler;
}> = [];

export function load() {
  if (isAndroid)
    pkgName = getPackageName();

  version = getOffsetsFromJSON();

  createMessageByType = new NativeFunction(
    base.add(Offsets.CreateMessageByType),
    "pointer",
    ["pointer", "int"],
  );
  operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", [
    "uint",
  ]);
  messageManagerReceiveMessage = new NativeFunction(
    base.add(
      isAndroid
        ? Offsets.MessageManagerReceiveMessage
        : Offsets.MessageManagerReceiveMessageThunk,
    ),
    "int",
    ["pointer", "pointer"],
  );
  stringCtor = new NativeFunction(
    base.add(Offsets.StringConstructor),
    "pointer",
    ["pointer", "pointer"],
  );
  messagingSend = new NativeFunction(base.add(Offsets.Send), "bool", [
    "pointer",
    "pointer",
  ]);
  setTextAndScaleIfNecessary = new NativeFunction(
    base.add(Offsets.SetTextAndScaleIfNecessary),
    "void",
    ["pointer", "pointer", "bool", "bool"],
  );
  getString = new NativeFunction(
    base.add(
      isAndroid
        ? Offsets.StringTableGetString
        : Offsets.StringTableGetStringThunk,
    ),
    "pointer",
    ["pointer"],
  );
  setText = new NativeFunction(base.add(Offsets.SetText), "int64", [
    "pointer",
    "pointer",
  ]);
  getMovieClip = new NativeFunction(base.add(Offsets.GetMovieClip), "pointer", [
    "pointer",
    "pointer",
    "bool",
  ]);
  gameButtonConstructor = new NativeFunction(
    base.add(Offsets.GameButtonConstructor),
    "void",
    ["pointer"],
  );
  addChild = new NativeFunction(base.add(Offsets.SpriteAddChild), "void", [
    "pointer",
    "pointer",
  ]);
  gotoAndStop = new NativeFunction(
    base.add(Offsets.GotoAndStopFrameIndex),
    "void",
    ["pointer", "int"],
  );
  getTextFieldByName = new NativeFunction(
    base.add(Offsets.GetTextFieldByName),
    "pointer",
    ["pointer", "pointer"],
  );
  getX = new NativeFunction(base.add(Offsets.GetX), "float", ["pointer"]);
  setX = new NativeFunction(base.add(Offsets.SetX), "void", [
    "pointer",
    "float",
  ]);
  getY = new NativeFunction(base.add(Offsets.GetY), "float", ["pointer"]);
  setY = new NativeFunction(base.add(Offsets.SetY), "void", [
    "pointer",
    "float",
  ]);
  setXY = new NativeFunction(base.add(Offsets.SetXY), "void", [
    "pointer",
    "float",
    "float",
  ]);
  getWidth = new NativeFunction(base.add(Offsets.GetWidth), "float", [
    "pointer",
  ]);
  setWidth = new NativeFunction(base.add(Offsets.SetWidth), "void", [
    "pointer",
    "float",
  ]);
  getHeight = new NativeFunction(base.add(Offsets.GetHeight), "float", [
    "pointer",
  ]);
  setHeight = new NativeFunction(base.add(Offsets.SetHeight), "void", [
    "pointer",
    "float",
  ]);
  setMultiline = new NativeFunction(base.add(Offsets.SetMultiline), "void", [
    "pointer",
    "bool",
  ]);
  autoAdjustText = new NativeFunction(
    base.add(Offsets.AutoAdjustText),
    "void",
    ["pointer", "int", "int", "int"],
  );
  getFontSize = new NativeFunction(base.add(Offsets.GetFontSize), "int", [
    "pointer",
  ]);
  setFontSize = new NativeFunction(base.add(Offsets.SetFontSize), "void", [
    "pointer",
    "int",
  ]);
  loadAsset = new NativeFunction(base.add(Offsets.LoadAsset), "bool", [
    "pointer",
    "bool",
  ]);
  setVerticallyCentered = new NativeFunction(
    base.add(Offsets.SetTextFieldVerticallyCentered),
    "void",
    ["pointer"],
  );
  showFloaterText = new NativeFunction(
    base.add(Offsets.ShowFloaterTextAtDefaultPos),
    "pointer",
    ["pointer", "pointer", "int64", "float"],
  );

  documentsDirectory = getDocumentsDirectory();
  configPath = documentsDirectory + "/config.json";
  config = readConfig();
  player.applyConfig(config);
}

export function setBase(ptr: NativePointer) {
  base = ptr;
}

export const credits = `NBS Offline

Made by Natesworks 
Telegram: t.me/nbsoffline
Discord: dsc.gg/nbsoffline

SPECIAL THANKS TO

S.B:
- Making an amazing guide on reverse engineering/making Brawl Stars Offline
- Answering my questions when I didn't understand something

xXCooBloyXx:
- Telling me how to get some of the required offsets for sendOfflineMessage

kubune:
- Player profile message 
- Ranked reputation
- Helping me when I'm an idiot

banaanae:
- Draft map limit config option allowing for more maps
`;

export function setBotNames(x: string[]) {
  botNames = x;
}
