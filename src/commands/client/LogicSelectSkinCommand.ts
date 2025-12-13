import { ByteStream } from "../../bytestream.js";
import { writeConfig } from "../../config.js";
import { config } from "../../definitions.js";
import { LogicCommand } from "../../logiccommand.js";

export class LogicSelectSkinCommand {
  static decode(stream: ByteStream): any {
    stream = LogicCommand.decode(stream);
    let skinID = stream.readDataReference().low;
    console.log("New skin id:", skinID);
    let unk1 = stream.readVint();
    return { stream, skinID };
  }

  static execute(skinID: number) {
    console.log("New skin id:", skinID);
    // todo
  }
}
