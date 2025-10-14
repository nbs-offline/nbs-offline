import { Config, readConfig, tryLoadDefaultConfig } from "./config.js";
import { Offsets } from "./offsets.js";
import { isAndroid } from "./platform.js";
import { Player } from "./player.js";
import { getDocumentsDirectory } from "./util.js";

export let base = NULL;

export const libc = isAndroid ? Process.getModuleByName('libc.so') : Process.getModuleByName('libSystem.B.dylib');

export const malloc = new NativeFunction(libc.getExportByName('malloc'), 'pointer', ['uint']);

export let player = new Player();
export let documentsDirectory: string;
export let configPath: string;
export let config: Config;

export let createMessageByType: NativeFunction<NativePointer, [NativePointer, number]>;
export let operator_new: NativeFunction<NativePointer, [number]>;
export let messageManagerReceiveMessage: NativeFunction<number, [NativePointerValue, NativePointerValue]>;
export let stringCtor: NativeFunction<NativePointer, [NativePointer, NativePointer]>;
export let messagingSend: NativeFunction<number, [NativePointer, NativePointer]>;
export let showFloaterText: NativeFunction<number, [NativePointer, NativePointer, number, number]>;

export function load() {
    createMessageByType = new NativeFunction(base.add(Offsets.CreateMessageByType), "pointer", ["pointer", "int"]);
    operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", ["uint"]);
    messageManagerReceiveMessage = new NativeFunction(base.add(isAndroid ? Offsets.MessageManagerReceiveMessage : Offsets.MessageManagerReceiveMessageThunk), "int", ["pointer", "pointer"]);
    stringCtor = new NativeFunction(base.add(Offsets.StringConstructor), "pointer", ["pointer", "pointer"]);
    messagingSend = new NativeFunction(base.add(Offsets.MessagingSend), "bool", ["pointer", "pointer"]);
    showFloaterText = new NativeFunction(base.add(Offsets.GUIShowFloaterTextAtDefaultPos), "int", ["pointer", "pointer", "int", "float"]);
    documentsDirectory = getDocumentsDirectory();
    configPath = documentsDirectory + "/config.json";
    config = readConfig();
    player.applyConfig(config);
}

export function setBase(ptr: NativePointer) {
    base = ptr;
}

export const credits = `NBS Offline v1

Made by Natesworks 
Discord: dsc.gg/nbsoffline

💙THANKS TO💙

S.B:
- Making an amazing guide on reverse engineering/making Brawl Stars Offline (peterr.dev/re/brawl-stars-offline).
- Answering my questions when I didn't understand something.

xXCooBloyXx:
- Telling me how to get some of the required offsets for sendOfflineMessage.
`