import { config, player } from "../../definitions.js";
import { ByteStream } from "../../bytestream.js";
import { Player } from "../../player";

export class TeamGameStartingMessage {
  static encode(): number[] {
    let stream = new ByteStream([]);

    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeDataReference({ high: 15, low: 10 });

    return stream.payload;
  }
}
