import { stringToUtf8Array, utf8ArrayToString } from "./util";

export class ByteStream {
    payload: number[];
    bitoffset: number;
    offset: number;

    constructor(payload: Uint8Array | number[]) {
        this.payload = Array.isArray(payload) ? [...payload] : Array.from(payload);
        this.bitoffset = 0;
        this.offset = 0;
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

    readString(maxCapacity: number = 512): string {
        this.bitoffset = 0;
        const previousOffset = this.offset;

        const length = this.readInt();
        if (length == -1) {
            return "";
        }

        if (length <= 0 || length > maxCapacity) {
            this.offset = previousOffset;
            throw new Error("invalid string length");
        }

        if (this.offset + length > this.payload.length) {
            this.offset = previousOffset;
            throw new Error("string length exceeds payload");
        }

        const bytes = this.payload.slice(this.offset, this.offset + length);
        this.offset += length;

        const decoded = utf8ArrayToString(new Uint8Array(bytes));

        return decoded;
    }

    writeDataReference(val: { high: number; low: number }): void {
        this.bitoffset = 0;
        this.writeVint(val.high);
        if (val.high != 0) {
            this.writeVint(val.low);
        }
    }

    readVint(): number {
        let start = this.offset;
        this.bitoffset = 0;
        if (start >= this.payload.length) {
            throw new Error("insufficient bytes for vint");
        }
        let b0 = this.payload[start];
        let result = b0 & 0x3F;
        this.offset = start + 1;
        if (b0 & 0x80) {
            if (this.offset >= this.payload.length) {
                throw new Error("insufficient bytes for vint");
            }
            let b1 = this.payload[this.offset];
            result |= (b1 & 0x7F) << 6;
            this.offset++;
            if (b1 & 0x80) {
                if (this.offset >= this.payload.length) {
                    throw new Error("insufficient bytes for vint");
                }
                let b2 = this.payload[this.offset];
                result |= (b2 & 0x7F) << 13;
                this.offset++;
                if (b2 & 0x80) {
                    if (this.offset >= this.payload.length) {
                        throw new Error("insufficient bytes for vint");
                    }
                    let b3 = this.payload[this.offset];
                    result |= (b3 & 0x7F) << 20;
                    this.offset++;
                    if (b3 & 0x80) {
                        if (this.offset >= this.payload.length) {
                            throw new Error("insufficient bytes for vint");
                        }
                        let b4 = this.payload[this.offset];
                        result |= (b4 & 0xF) << 27;
                        this.offset++;
                    }
                }
            }
        }
        if (b0 & 0x40) {
            let extra_bytes = this.offset - start - 1;
            let total_bits = 6 + 7 * extra_bytes;
            if (extra_bytes === 4) {
                total_bits -= 3;
            }
            let pow = 1 << total_bits;
            result -= pow;
        }
        return result;
    }

    readVlong(): number {
        let high = this.readVint();
        let low = this.readVint();
        return Number((BigInt(high) << 32n) | BigInt(low >>> 0));
    }

    readBoolean(): boolean {
        const val = (this.payload[this.offset] >> this.bitoffset) & 1;
        this.bitoffset = (this.bitoffset + 1) & 7;
        if (this.bitoffset === 0) this.offset++;
        return val !== 0;
    }

    readDataReference(): { high: number; low: number } {
        const high = this.readVint();
        if (high === 0) {
            return { high: 0, low: 0 };
        }
        const low = this.readVint();
        return { high, low };
    }

    writeByte(value: number): void {
        this.bitoffset = 0;
        this.payload.push(value & 0xFF);
        this.offset++;
    }

    writeShort(value: number): void {
        this.bitoffset = 0;
        this.payload.push((value >> 8) & 0xFF);
        this.payload.push(value & 0xFF);
        this.offset += 2;
    }

    writeInt(value: number): void {
        this.bitoffset = 0;
        this.payload.push((value >> 24) & 0xFF);
        this.payload.push((value >> 16) & 0xFF);
        this.payload.push((value >> 8) & 0xFF);
        this.payload.push(value & 0xFF);
        this.offset += 4;
    }

    writeIntLE(value: number): void {
        this.bitoffset = 0;
        this.payload.push(value & 0xFF);
        this.payload.push((value >> 8) & 0xFF);
        this.payload.push((value >> 16) & 0xFF);
        this.payload.push((value >> 24) & 0xFF);
        this.offset += 4;
    }

    writeString(str: string): void {
        this.bitoffset = 0;
        if (str.length == 0) {
            this.writeHexa("FFFFFFFF");
            return;
        }
        let bytes = stringToUtf8Array(str);
        this.writeInt(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
            this.writeByte(bytes[i]);
        }
    }

    writeVint(value: number): void {
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

    writeVlong(val: { high: number; low: number }): void {
        this.bitoffset = 0;
        this.writeVint(val.high);
        this.writeVint(val.low);
    }

    writeBoolean(value: boolean): void {
        if (this.bitoffset == 0) {
            this.payload.push(0);
            this.offset++;
        }
        if (value) {
            this.payload[this.offset - 1] |= 1 << (this.bitoffset & 7);
        }
        this.bitoffset = (this.bitoffset + 1) & 7;
    }

    writeLong(long: { high: number; low: number }): void {
        this.bitoffset = 0;
        this.writeInt(long.high);
        this.writeInt(long.low);
    }

    addCommodityArrayValue(csvID: number, rowID: number, Value: number) {
        this.writeDataReference({ high: csvID, low: rowID });
        this.writeVint(-1);
        this.writeVint(Value);
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