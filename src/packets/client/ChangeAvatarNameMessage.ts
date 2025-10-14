import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Messaging } from "../../messaging.js";
import { AvatarNameCheckResponseMessage as AvatarNameCheckResponseMessage } from "../server/AvatarNameCheckResponseMessage.js";
import { LogicChangeAvatarNameCommand } from "../../commands/LogicChangeAvatarNameCommand.js";
import { config } from "../../definitions.js";
import { writeConfig } from "../../config.js";

export class ChangeAvatarNameMessage {
    static decode(player: Player, stream: ByteStream): string {
        return stream.readString(); // theres also a bool but who gives a shit
    }

    static execute(player: Player, stream: ByteStream): void {
        player.name = this.decode(player, stream);
        console.log("Changed name to", player.name);
        Messaging.sendOfflineMessage(24111, LogicChangeAvatarNameCommand.encode(player));
        config.name = player.name;
        writeConfig(config);
    }
}