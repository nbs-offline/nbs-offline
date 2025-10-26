import { Offsets } from "./offsets";
import { base, debugLoaded, } from "./definitions";
import { installOfflineHooks } from "./offline";
import { Config } from "./config";
import { backtrace, decodeString, nop } from "./util";
import { PiranhaMessage } from "./piranhamessage";
import { addDebugFile, createDebugButton, setup } from "./debugmenu";

export function installHooks() {
    setup();

    Interceptor.attach(base.add(Offsets.HomeModeEnter),
        {
            onLeave(retval) {
                //createDebugButton();
            },
        });

    Interceptor.attach(base.add(Offsets.LogicDailyDataGetIntValue),
        {
            onEnter(args) {
                let key = args[1].toInt32();
                if (key == 15) {
                    this.replacement = ptr(0);
                }
            },
            onLeave(retval) {
                if (this.replacement) retval.replace(this.replacement);
            },
        });

    Interceptor.attach(base.add(Offsets.DebuggerError),
        {
            onEnter(args) {
                console.log("ERROR:", args[0].readCString());
            },
        });

    Interceptor.attach(base.add(Offsets.DebuggerWarning),
        {
            onEnter(args) {
                console.log("WARN:", args[0].readCString());
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
                retval.replace(ptr(1));
            },
        });

    Interceptor.attach(base.add(Offsets.IsDev),
        {
            onLeave(retval) {
                retval.replace(ptr(1));
            },
        });

    if (Config.offlineBattles) {
        Interceptor.attach(base.add(Offsets.HomePageStartGame),
            {
                onEnter: function (args) {
                    args[3] = ptr(3);
                }
            });
    }

    if (Config.dumpPackets && !Config.offline) {
        const sendMsg = new NativeFunction(base.add(Offsets.MessageManagerSendMessage), "int", ["pointer", "pointer"])
        Interceptor.replace(base.add(Offsets.MessageManagerSendMessage), new NativeCallback(function (messageManager: NativePointer, message: NativePointer) {
            //backtrace(this.context);
            PiranhaMessage.encode(message);
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
                console.log("Stream dump:\n", hexdump(payload));
            }

            //PiranhaMessage.destroyMessage(message);
            sendMsg(messageManager, message);

            return 1;
        }, "int", ["pointer", "pointer"]));

        Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage),
            {
                onEnter(args) {
                    let message = args[1];
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
                        console.log("Stream dump:\n", hexdump(payload));
                    }
                },
            });
    }

    Interceptor.attach(base.add(Offsets.LogicConfDataIsModuloOn),
        {
            onEnter(args) {
                let id = args[2].toUInt32();
                //console.log(id);
            },
            onLeave(retval) {
                if (this.value) retval.replace(ptr(this.value));
            },
        });

    if (Config.offline) installOfflineHooks();
    console.log("Done");
}