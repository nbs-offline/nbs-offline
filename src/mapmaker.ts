import { isAndroid } from "./platform";
import { getPackageName, utf8ArrayToString } from "./util";
import { Logger } from "./utility/logger";

const open = new NativeFunction(Module.getExportByName(null, "open"), "int", ["pointer", "int", "int"]);
const write = new NativeFunction(Module.getExportByName(null, "write"), "int", ["int", "pointer", "int"]);
const close = new NativeFunction(Module.getExportByName(null, "close"), "int", ["int"]);
const mkdir = new NativeFunction(Module.getExportByName(null, "mkdir"), "int", ["pointer", "int"]);
const read = new NativeFunction(Module.getExportByName(null, "read"), "int", ["int", "pointer", "int"]);
const opendir = new NativeFunction(Module.getExportByName(null, "opendir"), "pointer", ["pointer"]);
const readdir = new NativeFunction(Module.getExportByName(null, "readdir"), "pointer", ["pointer"]);
const closedir = new NativeFunction(Module.getExportByName(null, "closedir"), "int", ["pointer"]);
const unlink = new NativeFunction(Module.getExportByName(null, "unlink"), "int", ["pointer"]);


export function setupMapMaker() {
    if (!isAndroid) return;

    const pkg = getPackageName();
    if (!pkg) return;

    const basePath = `/storage/emulated/0/Android/media/${pkg}`;
    const mapDir = `${basePath}/mapmaker`;

    // mkdir base path (ignore errors if it exists)
    mkdir(Memory.allocUtf8String(basePath), 0o755);
    mkdir(Memory.allocUtf8String(mapDir), 0o755);
}

export function writeMapToFile(
    id: number[],
    name: string,
    gmv: number,
    theme: number,
    map: string,
    overwrite: boolean
) {
    const pkg = getPackageName();
    if (!pkg) return;

    const path = `/storage/emulated/0/Android/media/${pkg}/mapmaker/${id[0]}-${id[1]}.txt`;
    const oldMap = readMapFile(`${id[0]}-${id[1]}.txt`)

    let mapObj: PlayerMapFile;

    if (oldMap !== null) {
        mapObj = {
            name: (name !== "" ? name : oldMap.name),
            gmv: (gmv !== -1 ? gmv : oldMap.gmv),
            theme: (theme !== -1 ? theme : oldMap.theme),
            map: (map !== "" ? map : oldMap.map)
        }
        if (!overwrite) {
            mapObj.map = oldMap.map
        }
    } else {
        mapObj = {
            name: name,
            gmv: gmv,
            theme: theme,
            map: map
        }
    }

    map = JSON.stringify(mapObj)

    const data = Memory.allocUtf8String(map);
    const len = map.length;

    const flags = 0x241 // O_WRONLY | O_CREAT | O_TRUNC
        // 0x0C1; // O_WRONLY | O_CREAT | O_EXC
        // No overwrite (now unused)

    const fd = open(
        Memory.allocUtf8String(path),
        flags,
        0o644
    );

    if (fd < 0) {
        Logger.error("Failed to write map") // TODO: pass to response messages
        return;
    }

    write(fd, data, len);
    close(fd);
}

type PlayerMapFile = {
    name: string;
    gmv: number;
    theme: number;
    map: string;
}

export function readMapFile(fileName: string): PlayerMapFile | null {
    const pkg = getPackageName();

    const path = `/storage/emulated/0/Android/media/${pkg}/mapmaker/${fileName}`;

    const fd = open(
        Memory.allocUtf8String(path),
        0x0, // O_RDONLY
        0
    );

    if (fd < 0) {
        Logger.info("Failed to open file:", path);
        return null;
    }

    const chunks: string[] = [];
    const BUF_SIZE = 4096;
    const buf = Memory.alloc(BUF_SIZE);

    while (true) {
        const n = read(fd, buf, BUF_SIZE);
        if (n <= 0) break;

        const bytes = new Uint8Array(buf.readByteArray(n) as ArrayBuffer);
        chunks.push(utf8ArrayToString(bytes));
    }

    close(fd);
    return JSON.parse(chunks.join(""));
}

function readDirentName(dirent: NativePointer): string {
    // struct dirent {
    //   ino_t d_ino;        // 8 bytes
    //   off_t d_off;        // 8 bytes
    //   unsigned short d_reclen; // 2 bytes
    //   unsigned char d_type;   // 1 byte
    //   char d_name[];     // starts at offset 19 -> aligned to 24
    // }

    const NAME_OFFSET = 24;
    return dirent.add(NAME_OFFSET).readUtf8String()!;
}

export function getMapCount(): number {
    const pkg = getPackageName();
    if (!pkg) return 0;

    const path = `/storage/emulated/0/Android/media/${pkg}/mapmaker`;
    const dir = opendir(Memory.allocUtf8String(path));

    if (dir.isNull()) {
        Logger.error("Failed to open map dir");
        return 0;
    }

    let count = 0;

    while (true) {
        const ent = readdir(dir);
        if (ent.isNull()) break;

        const name = readDirentName(ent);
        if (name === "." || name === "..") continue;

        count++;
    }

    closedir(dir);
    return count;
}

export function deleteMap(id: number[]): boolean {
    const pkg = getPackageName();
    if (!pkg) return false;

    const path = `/storage/emulated/0/Android/media/${pkg}/mapmaker/${id[0]}-${id[1]}.txt`;

    const res = unlink(Memory.allocUtf8String(path));
    return res === 0;
}
