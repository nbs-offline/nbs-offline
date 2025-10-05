import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";

export class PlayerProfileMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        stream.writeVlong(player.id);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(1);
        stream.writeVint(16);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(1);
        stream.writeVint(0);
        stream.writeVint(5);
        stream.writeVint(2);
        stream.writeVint(490);
        stream.writeVint(5);
        stream.writeVint(1);
        stream.writeVint(23);
        stream.writeVint(1);
        stream.writeVint(24);
        stream.writeVint(0);
        stream.writeVint(27);
        stream.writeVint(2025);
        
        // PlayerDisplayData; todo move to diff file
        stream.writeString(player.name);
        stream.writeVint(100);
        stream.writeVint(28000000 + player.thumbnail);
        stream.writeVint(43000000 + player.namecolor);
        stream.writeVint(0);

        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);

        return stream.payload;
    }
}