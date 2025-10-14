import { ByteStream } from "./bytestream.js";

export class LogicCommand {
    static encode(): number[] {
        let stream = new ByteStream([]);

        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVlong(0, 0);

        return stream.payload;
    }
}