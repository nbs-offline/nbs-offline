import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Messaging } from "../../messaging.js";
import { AvatarNameCheckResponseMessage as AvatarNameCheckResponseMessage } from "../server/AvatarNameCheckResponseMessage.js";

export class AvatarNameCheckRequestMessage {
    static decode(player: Player, stream: ByteStream): string {
        return stream.readString();
    }

    static execute(player: Player, stream: ByteStream): void {
        let name = this.decode(player, stream);
        Messaging.sendOfflineMessage(20300, AvatarNameCheckResponseMessage.encode(player, name));
    }
}