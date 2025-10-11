import { ByteStream } from "./bytestream";
import { base, messagingSend, player } from "./definitions";
import { Messaging } from "./messaging";
import { Offsets } from "./offsets";
import { LoginOkMessage } from "./packets/server/LoginOkMessage";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage";
import { PiranhaMessage } from "./piranhamessage";
import { backtrace } from "./util";

export function installOfflineHooks() {

    Interceptor.replace(base.add(0x6b0980), new NativeCallback(function (self) {
        console.log("Mode:", self.add(160).readS32());
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
        Messaging.handleMessage(message);
        PiranhaMessage.destroyMessage(message);

        return 1;
    }, "int", ["pointer", "pointer"]));

    Interceptor.replace(
        base.add(Offsets.MessagingSend),
        new NativeCallback(function (self, message) {
            //backtrace(this.context);
            PiranhaMessage.encode(message);
            Messaging.handleMessage(message);
            PiranhaMessage.destroyMessage(message);

            return 0;
        }, "int", ["pointer", "pointer"])
    );

    Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage),
        {
            onEnter(args) {
                let message = args[1];
                let type = PiranhaMessage.getMessageType(message);
                let length = PiranhaMessage.getEncodingLength(message);

                console.log("Received message");
                console.log("Type:", type);
                console.log("Length:", length);
            },
            onLeave(retval) {
                retval.replace(ptr(1));
            }
        });

    Interceptor.attach(base.add(Offsets.LogicClientHomeIsEventSlotLocked),
        {
            onLeave(retval) {
                retval.replace(ptr(0));
            },
        });
}