import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import { base, documentsDirectory, messagingSend, player, stringCtor, } from "./definitions.js";
import { Messaging } from "./messaging.js";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage.js";
import { createStringObject, decodeString, getDocumentsDirectory, strPtr } from "./util.js";
import { BattleEndMessage } from "./packets/server/BattleEndMessage.js";
import { ByteStream } from "./bytestream.js";
import { AskForBattleEndMessage } from "./packets/client/AskForBattleEndMessage.js";
import { isAndroid } from "./platform.js";
import { PlayerProfileMessage } from "./packets/server/PlayerProfileMessage.js";
import { AvatarNameCheckRequestMessage } from "./packets/client/AvatarNameCheckRequestMessage.js";
import { ChangeAvatarNameMessage } from "./packets/client/ChangeAvatarNameMessage.js";

export function installHooks() {
    Interceptor.attach(base.add(Offsets.DebuggerError),
        {
            onEnter(args) {
                console.log("ERROR:", args[0].readCString());
            },
        });

    Interceptor.attach(base.add(Offsets.ServerConnectionUpdate),
        {
            onEnter: function (args) {
                args[0].add(Process.pointerSize).readPointer().add(Offsets.HasConnectFailed).writeU8(0);
                args[0].add(Process.pointerSize).readPointer().add(Offsets.State).writeInt(5);
            }
        });

    Interceptor.attach(base.add(Offsets.IsDev),
        {
            onLeave(retval) {
                retval.replace(ptr(1));
            },
        });

    Interceptor.attach(base.add(Offsets.IsDeveloperBuild),
        {
            onLeave(retval) {
                retval.replace(ptr(1));
            },
        });

    Interceptor.attach(base.add(Offsets.IsProd),
        {
            onLeave(retval) {
                retval.replace(ptr(0));
            },
        });

    Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage),
        {
            onLeave: function (retval) {
                retval.replace(ptr(1));
            }
        });

    Interceptor.attach(base.add(Offsets.HomePageStartGame),
        {
            onEnter: function (args) {
                args[3] = ptr(3);
            }
        });

    Interceptor.attach(base.add(Offsets.MessageManagerSendMessage),
        {
            onEnter(args) {
                PiranhaMessage.encode(args[1]);
                let messaging = args[0].add(Offsets.Messaging).readPointer();
                messaging.add(Offsets.State).writeInt(5);
            },
        });

    Interceptor.replace(base.add(Offsets.MessageManagerSendKeepAliveMessage), new NativeCallback(function () { }, "void", []));

    Interceptor.replace(
        base.add(Offsets.MessagingSend),
        new NativeCallback(function (self, message) {
            let type = PiranhaMessage.getMessageType(message);
            let length = PiranhaMessage.getEncodingLength(message);

            console.log("Type:", type);
            console.log("Length:", length);
            let payloadPtr = PiranhaMessage.getByteStream(message).add(Offsets.PayloadPtr).readPointer();
            let payload = payloadPtr.readByteArray(length);
            if (payload !== null) {
                let stream = new ByteStream(Array.from(new Uint8Array(payload)));
                console.log("Stream dump:", payload);

                if (type == 10100) { // ifs > switch
                    Messaging.sendOfflineMessage(20104, []);
                    Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
                } else if (type == 17750) {
                    Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode(player));
                } else if (type == 14110) { // erm execute shouldn't have these args :nerd:
                    AskForBattleEndMessage.execute(player, stream);
                } else if (type == 15081) { // get da profile
                    Messaging.sendOfflineMessage(24113, PlayerProfileMessage.encode(player));
                } else if (type == 14600) { // avatar name check request
                    AvatarNameCheckRequestMessage.execute(player, stream);
                } else if (type == 10212) { // change avatar name message
                    ChangeAvatarNameMessage.execute(player, stream);
                }
            }

            PiranhaMessage.destroyMessage(message);

            return 0;
        }, "int", ["pointer", "pointer"])
    );

    Interceptor.attach(base.add(Offsets.TutorialThingy),
        {
            onLeave(retval) {
                retval.replace(ptr(-1));
            },
        });

    /*
    Interceptor.attach(base.add(Offsets.NativeFontFormatString),
        {
            onEnter(args) {
                args[7] = ptr(1);
            },
        });
    */

    console.log("Done");
}