import { ByteStream } from "../../bytestream.js";
import { writeConfig } from "../../config.js";
import { config } from "../../definitions.js";
import { LogicCommand } from "../../logiccommand.js";

export class LogicSetPlayerThumbnailCommand {
  static decode(stream: ByteStream): any {
    stream = LogicCommand.decode(stream);
    let thumbnailID = stream.readDataReference().low;
    return { stream, thumbnailID };
  }

  static execute(thumbnailID: number) {
    console.log("New thumbnail id:", thumbnailID);
    config.thumbnail = thumbnailID;
    writeConfig(config);
  }
}
