import { Offsets } from "./offsets";
import { base, createMessageByType, debugLoaded, malloc, messageManagerReceiveMessage, operator_new, player } from "./definitions";
import { PiranhaMessage } from "./piranhamessage";
import { decodeString, getMessageManagerInstance } from "./util";
import { ByteStream } from "./bytestream";
import { LoginOkMessage } from "./packets/server/LoginOkMessage";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage";
import { Config } from "./config";
import { PlayerProfileMessage } from "./packets/server/PlayerProfileMessage";
import { createDebugButton, setup } from "./debugmenu";

export class Messaging {
    static handleMessage(message: NativePointer) {
        let type = PiranhaMessage.getMessageType(message);
        let length = PiranhaMessage.getEncodingLength(message);

        console.log("Type:", type);
        console.log("Length:", length);
        let payloadPtr = PiranhaMessage.getByteStream(message).add(Offsets.PayloadPtr).readPointer();
        let payload: ArrayBuffer | null = null;
        try {
            payload = payloadPtr.readByteArray(length);
        } catch {
            payloadPtr = PiranhaMessage.getByteStream(message).add(Offsets.PayloadPtr).readPointer();
            payload = payloadPtr.readByteArray(length);
        }

        if (payload !== null && length != 0) {
            let stream = new ByteStream(Array.from(new Uint8Array(payload)));
            if (Config.dumpPackets)
                console.log("Stream dump:\n", hexdump(payload));
        }

        if (type == 10100) { // ifs > switch
            Messaging.sendOfflineMessage(20104, LoginOkMessage.encode(player));
            Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
        }
        else if (type == 17750) {
            Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
        } else if (type == 14110) { // erm execute shouldn't have these args :nerd:
            //AskForBattleEndMessage.execute(player, stream);
        } else if (type == 15081) {
            Messaging.sendOfflineMessage(24113, PlayerProfileMessage.encode(player));
        }
    }

    static sendOfflineMessage(id: number, payload: number[]): NativePointer {
        let version = id == 20104 ? 1 : 0;
        let message = createMessageByType(NULL, id);
        console.log(message);
        message.add(Offsets.Version).writeInt(version);
        PiranhaMessage.getByteStream(message).add(Offsets.PayloadSize).writeInt(payload.length);
        if (payload.length > 0) {
            let payloadPtr = operator_new(payload.length).writeByteArray(payload);
            PiranhaMessage.getByteStream(message).add(Offsets.PayloadPtr).writePointer(payloadPtr);
        }
        let decode = message
            .readPointer()
            .add(Offsets.Decode)
            .readPointer();
        console.log("Decode function:", decode.sub(base));
        let decodeFn = new NativeFunction(
            decode,
            "int",
            ["pointer"]
        );
        try {
            let res = decodeFn(message);
            console.log("Message decoded with return value", res);
        } catch (e) {
            console.log("Failed to decode message", e);
        }
        console.log(message);
        try {
            messageManagerReceiveMessage(getMessageManagerInstance(), message);
        }
        catch (e) {}

        console.log("Message received");
        return message;
    }
}