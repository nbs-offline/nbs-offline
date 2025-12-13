import { ByteStream } from "../../bytestream.js";
import { config } from "../../definitions.js";
import { LogicCommand } from "../../logiccommand.js";

export class LogicChangeAvatarNameCommand {
  static encode(): number[] {
    let stream = new ByteStream([]);

    stream.writeVint(201);
    stream.writeString(config.name);
    stream.writeVint(0);
    stream.payload.concat(LogicCommand.encode());

    return stream.payload;
  }
}
