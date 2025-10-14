import { Player } from "../player.js";
import { ByteStream } from "../bytestream.js";
import { LogicCommand } from "../logiccommand.js";

export class LogicChangeAvatarNameCommand {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);

        stream.writeVint(201);
        stream.writeString(player.name);
        stream.writeVint(0);   
        stream.payload.concat(LogicCommand.encode());   

        return stream.payload;
    }
}