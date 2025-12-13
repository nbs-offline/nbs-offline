import { Player } from "../../../player.js";
import { ByteStream } from "../../../bytestream.js";
import { Messaging } from "../../../messaging.js";
import { config } from "../../../definitions.js";
import { writeConfig } from "../../../config.js";
import { SetSupportedCreatorResponseMessage } from "../../server/SetSupportedCreatorResponseMessage.js";
import { LogicSetSupportedCreatorCommand } from "../../../commands/server/LogicSetSupportedCreatorCommand.js";
import { PlayerMap } from "../../../playermap";
import { CreatePlayerMapResponseMessage } from "../../server/mapmaker/CreatePlayerMapResponseMessage.js";

export class CreatePlayerMapMessage {
  static decode(stream: ByteStream): PlayerMap {
    let mapName = stream.readString();
    let gmv = stream.readVint();
    let theme = stream.readDataReference().low;
    return new PlayerMap(mapName, gmv, theme);
  }

  static execute(map: PlayerMap) {
    Messaging.sendOfflineMessage(
      22100,
      CreatePlayerMapResponseMessage.encode(map),
    );
  }
}
