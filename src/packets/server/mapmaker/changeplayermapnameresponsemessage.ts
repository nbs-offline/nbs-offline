import { ByteStream } from "src/bytestream";
import { Long } from "src/long";

export class ChangePlayerMapNameResponseMessage {
    static encode(id: Long): number[] {
        let stream = new ByteStream([]);
    
        stream.writeVInt(0); // err
        stream.writeVLong(id.high, id.low);
    
        return stream.payload;
    }
}