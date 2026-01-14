import { ByteStream } from "../../../bytestream.js";
import { Messaging } from "../../../messaging.js";
import { PlayerMap } from "../../../playermap.js";
import { CreatePlayerMapResponseMessage } from "../../server/mapmaker/createplayermapresponsemessage.js";
import { getMapCount } from "src/mapmaker.js";

export class CreatePlayerMapMessage {
  static decode(stream: ByteStream): PlayerMap {
    let mapName = stream.readString();
    let gmv = stream.readVInt();
    let theme = stream.readDataReference().low;

    return new PlayerMap(mapName, gmv, theme, [0, getMapCount() + 1], []);
  }

  static execute(map: PlayerMap) {
    Messaging.sendOfflineMessage(
      22100,
      CreatePlayerMapResponseMessage.encode(map),
    );
  }
}
