import { config, player } from "../../../definitions.js";
import { ByteStream } from "../../../bytestream.js";
import { Player } from "../../../player";
import { PlayerMap } from "../../../playermap.js";

export class PlayerMapsMessage {
  static encode(player: Player): number[] {
    let stream = new ByteStream([]);

    stream.writeVint(1);
    let map = new PlayerMap("skidded from shei", 0, 0);
    map.avatarName = "hi";
    stream = map.encode(stream);

    return stream.payload;
  }
}
