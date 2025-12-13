import { ByteStream } from "../../../bytestream";
import { Player } from "../../../player";
import { PlayerMap } from "../../../playermap";

export class CreatePlayerMapResponseMessage {
  static encode(map: PlayerMap): number[] {
    let stream = new ByteStream([]);

    stream.writeVint(0);
    stream.writeBoolean(true);
    stream = map.encode(stream);

    return stream.payload;
  }
}
