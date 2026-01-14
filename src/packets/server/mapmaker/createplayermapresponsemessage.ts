import { ByteStream } from "../../../bytestream";
import { PlayerMap } from "../../../playermap";

export class CreatePlayerMapResponseMessage {
  static encode(map: PlayerMap): number[] {
    let stream = new ByteStream([]);

    stream.writeVInt(0);
    stream.writeBoolean(true);
    stream = map.encode(stream);

    return stream.payload;
  }
}
