import { Player } from "../../../player.js";
import { ByteStream } from "../../../bytestream.js";
import { Config } from "../../../config.js";
import { Long } from "../../../long.js"

export class DeletePlayerMapResponseMessage {
    static encode(player: Player, id: Long): number[] {
        let stream = new ByteStream([]);

        stream.writeVint(0); // err
        stream.writeVlong(id.high, id.low);

        return stream.payload;
    }
}
