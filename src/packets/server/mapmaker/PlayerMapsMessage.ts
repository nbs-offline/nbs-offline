import { ByteStream } from "../../../bytestream.js";
import { PlayerMap } from "../../../playermap.js";

export class PlayerMapsMessage {
  static encode(): number[] {
    let stream = new ByteStream([]);

    stream.writeVint(1);
    let map = new PlayerMap("Test", 0, 0);
    map.avatarName = "hi";
    stream = map.encode(stream);

    return stream.payload;
  }
}
