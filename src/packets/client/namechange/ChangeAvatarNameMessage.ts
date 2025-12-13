import { ByteStream } from "../../../bytestream.js";
import { Messaging } from "../../../messaging.js";
import { LogicChangeAvatarNameCommand } from "../../../commands/server/LogicChangeAvatarNameCommand.js";
import { config, player } from "../../../definitions.js";
import { writeConfig } from "../../../config.js";

export class ChangeAvatarNameMessage {
  static decode(stream: ByteStream): string {
    return stream.readString(); // theres also a bool but who gives a shit
  }

  static execute(name: string): void {
    player.name = name;
    config.name = name;
    config.registered = true;
    writeConfig(config);
    console.log("Changed name to", name);
    Messaging.sendOfflineMessage(24111, LogicChangeAvatarNameCommand.encode());
  }
}
