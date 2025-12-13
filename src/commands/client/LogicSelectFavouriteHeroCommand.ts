import { ByteStream } from "../../bytestream.js";
import { writeConfig } from "../../config.js";
import { config } from "../../definitions.js";
import { LogicCommand } from "../../logiccommand.js";

export class LogicSelectFavouriteHeroCommand {
  static decode(stream: ByteStream): any {
    stream = LogicCommand.decode(stream);
    let characterID = stream.readDataReference().low;
    return { stream, characterID };
  }

  static execute(characterID: number) {
    console.log("New favourite brawler id:", characterID);
    config.favouriteBrawler = characterID;
    writeConfig(config);
  }
}
