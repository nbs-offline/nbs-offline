import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";
import { toHex } from "../../util.js";

export class LoginOkMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        
        //console.log("LoginOK stream dump:\n", hexdump(new Uint8Array(stream.payload).buffer));

        return stream.payload;
    }
}