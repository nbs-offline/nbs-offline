import { base } from "./definitions";
import { nop } from "./util";

export function applyPatches() {
    nop([base.add(0x6b112c), base.add(0x6b1144)]);
    nop([base.add(0x6b242c)]);
    nop([base.add(0x6b21ec), base.add(0x6b21c4), base.add(0x6b21f0), base.add(0x943784)]);
    nop([base.add(0x9423f0), base.add(0x943bbc), base.add(0x943bc8)]);
}