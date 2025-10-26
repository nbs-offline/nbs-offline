import { Config, readConfig } from "./config";
import { readFile } from "./fs";
import { Offsets } from "./offsets";
import { isAndroid } from "./platform";
import { Player } from "./player";

export let base = NULL;

export const libc = isAndroid ? Process.getModuleByName('libc.so') : Process.getModuleByName('libSystem.B.dylib');

export const malloc = new NativeFunction(libc.getExportByName('malloc'), 'pointer', ['uint']);

export let player = new Player();

export let createMessageByType: NativeFunction<NativePointer, [NativePointer, number]>;
export let operator_new: NativeFunction<NativePointer, [number]>;
export let messageManagerReceiveMessage: NativeFunction<number, [NativePointerValue, NativePointerValue]>;
export let stringCtor: NativeFunction<NativePointer, [NativePointer, NativePointer]>;
export let messagingSend: NativeFunction<number, [NativePointer, NativePointer]>;
export let showFloaterText: NativeFunction<number, [NativePointer, NativePointer, number, number]>;

export let debugLoaded = false;
export let configPath: string;
export let pkg: string;
export let dataDirectory: string;
export let config: Config;

export function setDebugLoaded(val: boolean) {
    debugLoaded = val;
}

export function load() {
    createMessageByType = new NativeFunction(base.add(Offsets.CreateMessageByType), "pointer", ["pointer", "int"]);
    operator_new = new NativeFunction(base.add(Offsets.OperatorNew), "pointer", ["ulong"]);
    messageManagerReceiveMessage = new NativeFunction(base.add(Offsets.MessageManagerReceiveMessage), "int", ["pointer", "pointer"]);
    stringCtor = new NativeFunction(base.add(Offsets.StringConstructor), "pointer", ["pointer", "pointer"]);
    messagingSend = new NativeFunction(base.add(Offsets.MessagingSend), "bool", ["pointer", "pointer"]);
    showFloaterText = new NativeFunction(base.add(Offsets.GUIShowFloaterTextAtDefaultPos), "int", ["pointer", "pointer", "int", "float"]);

    pkg = readFile("/proc/self/cmdline").split("\0")[0];
    dataDirectory = `/storage/emulated/0/Android/data/${pkg}`;
    configPath = dataDirectory + "/config.json";
    config = readConfig();
    player.applyConfig();
}

export function setBase(ptr: NativePointer) {
    base = ptr;
}

export const credits = `NBS Offline v4 Alpha

Made by Natesworks 
Discord: dsc.gg/nbsoffline

💙THANKS TO💙

S.B:
- Making an amazing guide on reverse engineering/making Brawl Stars Offline (peterr.dev/re/brawl-stars-offline).
- Answering my questions when I didn't understand something.

xXCooBloyXx:
- Telling me how to get some of the required offsets for sendOfflineMessage.
`