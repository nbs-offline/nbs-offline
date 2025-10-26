import { base } from "./definitions";
import { nop } from "./util";

// stupid crash fixes and other shit
export function applyPatches() {
    nop(base.add(0x6b112c));
    nop(base.add(0x6b1144));
    nop(base.add(0x6b242c));
    nop(base.add(0x6b21ec));
    nop(base.add(0x6b21c4));
    nop(base.add(0x6b21f0));
    nop(base.add(0x943784));
    nop(base.add(0x9423f0));
    nop(base.add(0x943bbc));
    nop(base.add(0x943bc8));
}