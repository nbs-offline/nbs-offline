import { gAssetManager } from "./assetmanagerandroid.js";
import { Brawler } from "./brawler.js";
import { base, getString, malloc, pkgName, stringCtor } from "./definitions.js";
import { Offsets } from "./offsets.js";
import { isAndroid } from "./platform.js";

const read = new NativeFunction(
  Process.getModuleByName(
    isAndroid ? "libc.so" : "libSystem.B.dylib",
  ).getExportByName("read"),
  "int",
  ["int", "pointer", "int"],
);
export const open = new NativeFunction(
  Process.getModuleByName(
    isAndroid ? "libc.so" : "libSystem.B.dylib",
  ).getExportByName("open"),
  "int",
  ["pointer", "int", "int"],
);
export const close = new NativeFunction(
  Process.getModuleByName(
    isAndroid ? "libc.so" : "libSystem.B.dylib",
  ).getExportByName("close"),
  "int",
  ["int"],
);

export function getPackageName() {
  const buf = Memory.alloc(4096);
  const fd = open(Memory.allocUtf8String("/proc/self/cmdline"), 0, 0);
  const n = read(fd, buf, 4096);
  close(fd);
  if (n <= 0) return "";
  const arr = new Uint8Array(buf.readByteArray(n) as ArrayBuffer);
  return String.fromCharCode(...arr).replace(/\0+$/, "");
}

export function getMessageManagerInstance(): NativePointer {
  return base.add(Offsets.MessageManagerInstance).readPointer();
}

export function getDocumentsDirectory(): string {
  if (!isAndroid && ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    var fm = NSFileManager.defaultManager();

    let docsPath = fm
      .URLsForDirectory_inDomains_(9, 1)
      .objectAtIndex_(0)
      .path()
      .toString();
    return docsPath;
  } else {
    return `/data/data/${pkgName}`;
  }
}

export function getLibraryDirectory() {
  const maps = File.readAllText("/proc/self/maps");
  const lines = maps.split("\n");
  let libName = "libnbs.so"; // don't rename library

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 6) {
      const path = parts[5];
      if (path.includes(libName)) {
        const lastSlash = path.lastIndexOf("/");
        return lastSlash !== -1 ? path.slice(0, lastSlash) : path;
      }
    }
  }

  throw new Error("libnbs.so not found");
}

export function getDefaultConfig(): string {
  if (!isAndroid) {
    return getDefaultConfigIOS();
  }
  let cfg = gAssetManager?.readFromAssets("nbs/config.json");
  if (cfg) {
    return cfg;
  }
  throw new Error("Failed to read config.json. Has it been deleted?");
}

export function getDefaultConfigIOS(): string {
  var NSBundle = ObjC.classes.NSBundle,
    NSString = ObjC.classes.NSString,
    NSData = ObjC.classes.NSData,
    NSFileManager = ObjC.classes.NSFileManager;
  var path = NSBundle.mainBundle().bundlePath().toString() + "/config.json";
  if (
    !NSFileManager.defaultManager().fileExistsAtPath_(
      NSString.stringWithString_(path),
    )
  ) {
    throw new Error("Default config missing");
  }
  var data = NSData.dataWithContentsOfFile_(NSString.stringWithString_(path));
  var str = NSString.alloc().initWithData_encoding_(data, 4);
  return str.toString();
}

export function decodeString(src: NativePointer): string | null {
  let len = src.add(4).readInt();
  if (len >= 8) {
    return src.add(8).readPointer().readUtf8String(len);
  }
  return src.add(8).readUtf8String(len);
}

export function strPtr(message: string) {
  var charPtr = malloc(message.length + 1);
  charPtr.writeUtf8String(message);
  return charPtr;
}

export function createStringObject(text: string) {
  let ptr = malloc(128);
  stringCtor(ptr, strPtr(text));
  return ptr;
}

// cant use TextEncoder or TextDecoder in frida so skidded this thing
export function utf8ArrayToString(array: Uint8Array): string {
  let out = "",
    i = 0,
    len = array.length;
  while (i < len) {
    let c = array[i++];
    if (c < 128) {
      out += String.fromCharCode(c);
    } else if (c > 191 && c < 224) {
      let c2 = array[i++];
      out += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
    } else {
      let c2 = array[i++];
      let c3 = array[i++];
      out += String.fromCharCode(
        ((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63),
      );
    }
  }
  return out;
}

export function stringToUtf8Array(str: string): Uint8Array {
  let utf8 = [];
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i);
    if (charcode < 0x80) {
      utf8.push(charcode);
    } else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(
        0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f),
      );
    } else {
      i++;
      let surrogatePair =
        0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(
        0xf0 | (surrogatePair >> 18),
        0x80 | ((surrogatePair >> 12) & 0x3f),
        0x80 | ((surrogatePair >> 6) & 0x3f),
        0x80 | (surrogatePair & 0x3f),
      );
    }
  }
  return new Uint8Array(utf8);
}

export function waitForModule(
  name: string,
  intervalMs = 10,
): Promise<NativePointer> {
  return new Promise((resolve) => {
    const interval = setInterval(() => {
      const handle = Process.getModuleByName(name).base;
      if (handle) {
        clearInterval(interval);
        resolve(handle);
      }
    }, intervalMs);
  });
}

export function calculateTrophies(
  brawlerData: Record<number, Brawler>,
): number {
  let trophies = 0;
  for (const [_, brawler] of Object.entries(
    brawlerData as Record<string, any>,
  )) {
    trophies += brawler.highestTrophies;
  }
  return trophies;
}

export function calculateHighestTrophies(
  brawlerData: Record<number, Brawler>,
): number {
  let trophies = 0;
  for (const [_, brawler] of Object.entries(
    brawlerData as Record<string, any>,
  )) {
    trophies += brawler.highestTrophies;
  }
  return trophies;
}

// https://stackoverflow.com/a/2450976
export function shuffle(arr: string[]): string[] {
  let idx = arr.length;

  while (idx != 0) {
    let shuffledIdx = Math.floor(Math.random() * idx);
    idx--;
    [arr[idx], arr[shuffledIdx]] = [arr[shuffledIdx], arr[idx]];
  }

  return arr;
}

export function getBotNames(n: number): string[] {
  let arr: string[] = [];
  let i = 1;
  while (true) {
    let name = decodeString(
      getString(Memory.allocUtf8String("TID_BOT_" + i.toString())),
    );
    if (!name) throw new Error("name is null");
    if (i >= n && name.startsWith("TID_")) break;
    i++;
    arr.push(name);
  }
  return shuffle(arr);
}
