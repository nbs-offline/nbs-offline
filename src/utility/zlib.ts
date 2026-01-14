// You’re doing this the hard way — respect 😄
//  - ChatGPT

import { utf8ArrayToString } from "../util";

export class zlib {
    static compress(input: string): Uint8Array {
        const malloc = new NativeFunction(
            Module.getExportByName("libc.so", "malloc"),
            'pointer',
            ['ulong']
        );

        const free = new NativeFunction(
            Module.getExportByName("libc.so", "free"),
            'void',
            ['pointer']
        );

        const compress = new NativeFunction(
            Module.getExportByName("libz.so", "compress"),
            'int',
            ['pointer', 'pointer', 'pointer', 'ulong']
        );

        const inputLen = input.length;

        // Allocate input buffer
        const inBuf = malloc(inputLen);
        for (let i = 0; i < inputLen; i++) {
            inBuf.add(i).writeU8(input.charCodeAt(i));
        }

        // Allocate output buffer
        const maxOut = Math.floor(inputLen * 1.1) + 12;
        const outBuf = malloc(maxOut);

        const outLenPtr = malloc(4);
        outLenPtr.writeU32(maxOut);

        // Compress
        const res = compress(outBuf, outLenPtr, inBuf, inputLen);
        if (res !== 0) {
            free(inBuf);
            free(outBuf);
            free(outLenPtr);
            throw "zlib compress failed: " + res;
        }

        const compressedLen = outLenPtr.readU32();

        // Create Uint8Array
        const result = new Uint8Array(compressedLen);
        for (let i = 0; i < compressedLen; i++) {
            result[i] = outBuf.add(i).readU8();
        }

        // Cleanup native memory
        free(inBuf);
        free(outBuf);
        free(outLenPtr);

        return result;
    }

    static decompress(inputUint8: Uint8Array): string {
        const malloc = new NativeFunction(
            Module.getExportByName("libc.so", "malloc"),
            'pointer',
            ['ulong']
        );

        const free = new NativeFunction(
            Module.getExportByName("libc.so", "free"),
            'void',
            ['pointer']
        );

        const uncompress = new NativeFunction(
            Module.getExportByName("libz.so", "uncompress"),
            'int',
            ['pointer', 'pointer', 'pointer', 'ulong']
        );

        const inLen = inputUint8.length;

        // Allocate input buffer
        const inBuf = malloc(inLen);
        for (let i = 0; i < inLen; i++) {
            inBuf.add(i).writeU8(inputUint8[i]);
        }

        // Output size guess
        // zlib requires you to know (or guess) the decompressed size
        // Common strategy: grow buffer until it works
        let outSize = inLen * 4;
        let outBuf, outLenPtr, res;

        while (true) {
            outBuf = malloc(outSize);
            outLenPtr = malloc(4);
            outLenPtr.writeU32(outSize);

            res = uncompress(outBuf, outLenPtr, inBuf, inLen);

            if (res === 0) {
                break; // success
            }

            // Z_BUF_ERROR = -5 (buffer too small)
            free(outBuf);
            free(outLenPtr);

            if (res !== -5) {
                free(inBuf);
                throw "zlib uncompress failed: " + res;
            }

            outSize *= 2;
        }

        const finalLen = outLenPtr.readU32();

        // Copy to Uint8Array
        const result = new Uint8Array(finalLen);
        for (let i = 0; i < finalLen; i++) {
            result[i] = outBuf.add(i).readU8();
        }

        // Cleanup
        free(inBuf);
        free(outBuf);
        free(outLenPtr);

        return utf8ArrayToString(result);
    }
}