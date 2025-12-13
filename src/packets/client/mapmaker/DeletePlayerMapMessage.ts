import { ByteStream } from "../../../bytestream.js";
import { Messaging } from "../../../messaging.js";
import { Long } from "../../../long.js";
import { DeletePlayerMapResponseMessage } from "../../server/mapmaker/DeletePlayerMapResponseMessage.js";

export class DeletePlayerMapMessage {
  static decode(stream: ByteStream): Long {
    let id = stream.readVlongAsLong(); // map id
    return id;
  }

  static execute(id: Long): void {
    Messaging.sendOfflineMessage(
      22101,
      DeletePlayerMapResponseMessage.encode(id),
    );
  }
}
