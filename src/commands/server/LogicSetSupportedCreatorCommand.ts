import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { LogicCommand } from "../../logiccommand.js";
import { config } from "../../definitions.js";

export class LogicSetSupportedCreatorCommand {
  static encode(): number[] {
    let stream = new ByteStream([]);

    stream.writeVint(215);
    stream.writeBoolean(true);
    stream.writeString(config.supportedCreator);
    stream.payload.concat(LogicCommand.encode());

    return stream.payload;
  }
}
