import { ByteStream } from "./bytestream";
import { base, messagingSend, player } from "./definitions";
import { Messaging } from "./messaging";
import { Offsets } from "./offsets";
import { LoginOkMessage } from "./packets/server/LoginOkMessage";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage";
import { PiranhaMessage } from "./piranhamessage";
import { backtrace } from "./util";

export function handleMessage(message: NativePointer) {
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
    }
}

export function installOfflineHooks() {

    Interceptor.replace(base.add(0x6b0980), new NativeCallback(function (self) {
        self.add(160).writeS32(4); // switch mode mode always to 4 i guess
        return self;
    }, "pointer", ["pointer"]));

    Interceptor.attach(base.add(Offsets.TutorialState),
        {
            onLeave(retval) {
                retval.replace(ptr(-1));
            },
        });

    Interceptor.replace(base.add(0xa364ac), new NativeCallback(function () {
        return 0xFFFFFFFF;
    }, "int", []));

    Interceptor.attach(base.add(Offsets.ServerConnectionUpdate),
        {
            onEnter: function (args) {
                args[0].add(Process.pointerSize).readPointer().add(Offsets.HasConnectFailed).writeU8(0);
                args[0].add(Process.pointerSize).readPointer().add(Offsets.State).writeInt(5);
            }
        });

    Interceptor.replace(base.add(Offsets.MessageManagerSendMessage), new NativeCallback(function (messageManager: NativePointer, message: NativePointer) {
        //backtrace(this.context);
        PiranhaMessage.encode(message);
        handleMessage(message);
        PiranhaMessage.destroyMessage(message);

        return 1;
    }, "int", ["pointer", "pointer"]));

    Interceptor.replace(
        base.add(Offsets.MessagingSend),
        new NativeCallback(function (self, message) {
            //backtrace(this.context);
            PiranhaMessage.encode(message);
            handleMessage(message);
            PiranhaMessage.destroyMessage(message);

            return 0;
        }, "int", ["pointer", "pointer"])
    );

    Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage),
        {
            onLeave: function (retval) {
                retval.replace(ptr(1));
            }
        });
}