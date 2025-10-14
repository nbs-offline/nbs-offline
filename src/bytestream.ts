import { Long } from "./long.js";
import { utf8ArrayToString, stringToUtf8Array } from "./util.js";

export class ByteStream {
    payload: number[];
    bitoffset: number;
    offset: number;
    constructor(payload: number[]) {
        this.payload = payload;
        this.bitoffset = 0;
        this.offset = 0;
    }

    readBytesLength(): number {
        this.bitoffset = 0;
        const b1 = this.payload[this.offset++];
        const b2 = this.payload[this.offset++];
        const b3 = this.payload[this.offset++];
        const b4 = this.payload[this.offset++];
        return ((b1 << 24) >>> 0) | (b2 << 16) | (b3 << 8) | b4;
    }

    readInt(): number {
        this.bitoffset = 0;
        let result = ((this.payload[this.offset] << 24) >>> 0) | (this.payload[this.offset + 1] << 16) | (this.payload[this.offset + 2] << 8) | this.payload[this.offset + 3];
        this.offset += 4;
        return result;
    }

    readByte(): number {
        this.bitoffset = 0;
        let result = this.payload[this.offset];
        this.offset++;
        return result;
    }

    readShort(): number {
        this.bitoffset = 0;
        let result = (this.payload[this.offset] << 8) | this.payload[this.offset + 1];
        this.offset += 2;
        return result;
    }

    readLong(): number {
        this.bitoffset = 0;
        let high = this.readInt();
        let low = this.readInt();
        return Number((BigInt(high) << 32n) | BigInt(low >>> 0));
    }

    readString(maxCapacity: number = 9000000): string {
        this.bitoffset = 0;
        const length = this.readBytesLength();
        if (length < 0 || length > maxCapacity) {
            throw Error("invalid string length");
        }
        const bytes = this.payload.slice(this.offset, this.offset + length);
        this.offset += length;
        return utf8ArrayToString(new Uint8Array(bytes));
    }

    readStringReference(maxCapacity: number = 9000000): string {
        this.bitoffset = 0;
        const length = this.readBytesLength();
        if (length < 0 || length > maxCapacity) {
            return "";
        }
        const bytes = this.payload.slice(this.offset, this.offset + length);
        this.offset += length;
        return utf8ArrayToString(new Uint8Array(bytes));
    }

    writeDataReference(val: Long) {
        this.bitoffset = 0;
        this.writeVint(val.high);
        if (val.high != 0)
            this.writeVint(val.low);
    }

    readVint(): number {
        let start = this.offset;
        this.bitoffset = 0;
        let b0 = this.payload[start];
        this.offset = start + 1;
        let result = b0 & 0x3F;
        if (b0 & 0x40) {
            if (b0 & 0x80) {
                let b1 = this.payload[start + 1];
                result = result | ((b1 & 0x7F) << 6);
                this.offset = start + 2;
                if (b1 & 0x80) {
                    let b2 = this.payload[start + 2];
                    result = result | ((b2 & 0x7F) << 13);
                    this.offset = start + 3;
                    if (b2 & 0x80) {
                        let b3 = this.payload[start + 3];
                        result = result | ((b3 & 0x7F) << 20);
                        this.offset = start + 4;
                        if (b3 & 0x80) {
                            let b4 = this.payload[start + 4];
                            this.offset = start + 5;
                            result = result | (b4 << 27);
                        }
                    }
                }
            }
            result = -(result | (0xFFFFFFC0 << (((this.offset - start - 1) * 7) - 6)));
        } else if (b0 & 0x80) {
            let b1 = this.payload[start + 1];
            result = result | ((b1 & 0x7F) << 6);
            this.offset = start + 2;
            if (b1 & 0x80) {
                let b2 = this.payload[start + 2];
                result = result | ((b2 & 0x7F) << 13);
                this.offset = start + 3;
                if (b2 & 0x80) {
                    let b3 = this.payload[start + 3];
                    result = result | ((b3 & 0x7F) << 20);
                    this.offset = start + 4;
                    if (b3 & 0x80) {
                        let b4 = this.payload[start + 4];
                        this.offset = start + 5;
                        result = result | (b4 << 27);
                    }
                }
            }
        }
        return result;
    }

    readVlong(): number {
        let high = this.readVint();
        let low = this.readVint();
        return Number((BigInt(high) << 32n) | BigInt(low >>> 0));
    }

    readBoolean(): boolean {
        this.bitoffset = 0;
        return this.payload[this.offset++] !== 0;
    }

    readDataReference(): Long {
        const high = this.readVint();
        if (high === 0) {
            return { high: 0, low: 0 };
        }
        const low = this.readVint();
        return { high, low };
    }

    writeByte(value: number) {
        this.bitoffset = 0;
        this.payload.push(value & 0xFF);
        this.offset++;
    }

    writeShort(value: number) {
        this.bitoffset = 0;
        this.payload.push((value >> 8) & 0xFF);
        this.payload.push(value & 0xFF);
        this.offset += 2;
    }

    writeInt(value: number) {
        this.bitoffset = 0;
        this.payload.push((value >> 24) & 0xFF);
        this.payload.push((value >> 16) & 0xFF);
        this.payload.push((value >> 8) & 0xFF);
        this.payload.push(value & 0xFF);
        this.offset += 4;
    }

    writeString(str: string) {
        this.bitoffset = 0;
        let bytes = stringToUtf8Array(str);
        this.writeInt(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
            this.writeByte(bytes[i]);
        }
    }

    writeVint(value: number) {
        this.bitoffset = 0;
        if (value < 0) {
            if (value >= -63) {
                this.payload.push((value & 0x3F) | 0x40);
                this.offset += 1;
            } else if (value >= -8191) {
                this.payload.push((value & 0x3F) | 0xC0);
                this.payload.push((value >> 6) & 0x7F);
                this.offset += 2;
            } else if (value >= -1048575) {
                this.payload.push((value & 0x3F) | 0xC0);
                this.payload.push(((value >> 6) & 0x7F) | 0x80);
                this.payload.push((value >> 13) & 0x7F);
                this.offset += 3;
            } else if (value >= -134217727) {
                this.payload.push((value & 0x3F) | 0xC0);
                this.payload.push(((value >> 6) & 0x7F) | 0x80);
                this.payload.push(((value >> 13) & 0x7F) | 0x80);
                this.payload.push((value >> 20) & 0x7F);
                this.offset += 4;
            } else {
                this.payload.push((value & 0x3F) | 0xC0);
                this.payload.push(((value >> 6) & 0x7F) | 0x80);
                this.payload.push(((value >> 13) & 0x7F) | 0x80);
                this.payload.push(((value >> 20) & 0x7F) | 0x80);
                this.payload.push((value >> 27) & 0xF);
                this.offset += 5;
            }
        } else {
            if (value <= 63) {
                this.payload.push(value & 0x3F);
                this.offset += 1;
            } else if (value <= 8191) {
                this.payload.push((value & 0x3F) | 0x80);
                this.payload.push((value >> 6) & 0x7F);
                this.offset += 2;
            } else if (value <= 1048575) {
                this.payload.push((value & 0x3F) | 0x80);
                this.payload.push(((value >> 6) & 0x7F) | 0x80);
                this.payload.push((value >> 13) & 0x7F);
                this.offset += 3;
            } else if (value <= 134217727) {
                this.payload.push((value & 0x3F) | 0x80);
                this.payload.push(((value >> 6) & 0x7F) | 0x80);
                this.payload.push(((value >> 13) & 0x7F) | 0x80);
                this.payload.push((value >> 20) & 0x7F);
                this.offset += 4;
            } else {
                this.payload.push((value & 0x3F) | 0x80);
                this.payload.push(((value >> 6) & 0x7F) | 0x80);
                this.payload.push(((value >> 13) & 0x7F) | 0x80);
                this.payload.push(((value >> 20) & 0x7F) | 0x80);
                this.payload.push((value >> 27) & 0xF);
                this.offset += 5;
            }
        }
    }

    writeVlong(high: number, low: number) {
        this.bitoffset = 0;
        this.writeVint(high);
        this.writeVint(low);
    }

    writeBoolean(value: boolean) {
        if (this.bitoffset == 0) {
            this.payload.push(0);
            this.offset++;
        }
        if (value) {
            this.payload[this.offset - 1] |= 1 << (this.bitoffset & 7);
        }
        this.bitoffset = (this.bitoffset + 1) & 7;
    }

    writeLong(high: number, low: number) {
        this.bitoffset = 0;
        this.writeInt(high);
        this.writeInt(low);
    }

    writeHexa(hex: string): void {
        for (let i = 0; i < hex.length; i += 2) {
            const byteStr = hex.substring(i, i + 2);
            const byte = parseInt(byteStr, 16);

            if (isNaN(byte)) {
                throw new Error(`invalid hex: ${byteStr}`);
            }

            this.writeByte(byte);
        }
    }
}