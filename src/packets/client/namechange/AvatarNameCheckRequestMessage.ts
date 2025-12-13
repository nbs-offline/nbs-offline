import { Player } from "../../../player.js";
import { ByteStream } from "../../../bytestream.js";
import { Messaging } from "../../../messaging.js";
import { AvatarNameCheckResponseMessage } from "../../server/namechange/AvatarNameCheckResponseMessage.js";

export class AvatarNameCheckRequestMessage {
  static decode(stream: ByteStream): string {
    return stream.readString();
  }

  static execute(name: string): void {
    Messaging.sendOfflineMessage(
      20300,
      AvatarNameCheckResponseMessage.encode(name),
    );
  }
}
