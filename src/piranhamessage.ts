import { base } from "./definitions.js";
import { Offsets } from "./offsets.js";

export class PiranhaMessage {
    static getMessageType(message: NativePointer): number {
        let vtable = message.readPointer();
        let getMessageType = new NativeFunction(vtable.add(Offsets.GetMessageType).readPointer(), 'int', []);
        return getMessageType();
    }

    static destroyMessage(message: NativePointer): void {
        let vtable = message.readPointer();
        let destroyMessage = new NativeFunction(vtable.add(Offsets.Destruct).readPointer(), 'void', ['pointer']);
        return destroyMessage(message); // no need to ret but looks better imo
    }

    static getEncodingLength(message: NativePointer): number {
        let stream = this.getByteStream(message);
        let size = stream.add(Offsets.PayloadSize).readS32();
        let offset = stream.add(Offsets.ByteStreamOffset).readS32();
        return offset > size ? offset : size;
    }

    static getByteStream(message: NativePointer): NativePointer {
        return message.add(Offsets.ByteStream);
    }

    static encode(message: NativePointer): NativePointer {
        let vtable = message.readPointer();
        const encode = new NativeFunction(vtable.add(Offsets.Encode).readPointer(), 'pointer', ['pointer']);
        return encode(message);
    }

    static decode(message: NativePointer): NativePointer {
        let vtable = message.readPointer();
        const decode = new NativeFunction(vtable.add(Offsets.Decode).readPointer(), 'pointer', ['pointer']);
        return decode(message);
    }
}
