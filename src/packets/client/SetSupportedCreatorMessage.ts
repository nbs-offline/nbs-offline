import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Messaging } from "../../messaging.js";
import { config } from "../../definitions.js";
import { writeConfig } from "../../config.js";
import { SetSupportedCreatorResponseMessage } from "../server/SetSupportedCreatorResponseMessage.js";
import { LogicSetSupportedCreatorCommand } from "../../commands/server/LogicSetSupportedCreatorCommand.js";

export class SetSupportedCreatorMessage {
  static decode(stream: ByteStream) {
    let ccc = stream.readString();
    return ccc;
  }

  static execute(ccc: string) {
    if (ccc == "") {
      console.log("Clearing CCC");
    } else {
      console.log("New CCC:", ccc);
    }
    if (
      ccc != "" &&
      !config.allCreatorCodesValid &&
      !config.creatorCodes.includes(ccc)
    ) {
      return Messaging.sendOfflineMessage(
        28686,
        SetSupportedCreatorResponseMessage.encode(),
      );
    }
    config.supportedCreator = ccc;
    writeConfig(config);
    Messaging.sendOfflineMessage(
      24111,
      LogicSetSupportedCreatorCommand.encode(),
    );
  }
}
