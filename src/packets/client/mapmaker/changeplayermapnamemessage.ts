import { ByteStream } from "src/bytestream";
import { Long } from "src/long";
import { writeMapToFile } from "src/mapmaker";
import { Messaging } from "src/messaging";
import { ChangePlayerMapNameResponseMessage } from "src/packets/server/mapmaker/changeplayermapnameresponsemessage";

export class ChangePlayerMapNameMessage {
    static decode(stream: ByteStream): Long {
        let id = stream.readVLongAsLong()
        let newName = stream.readString()

        writeMapToFile([id.high, id.low], newName, -1, -1, "", false)

        return id
    }

    static execute(id: Long) {
        Messaging.sendOfflineMessage(22106,
            ChangePlayerMapNameResponseMessage.encode(id)
        )
    }
}