import { Offsets } from "./offsets";
import { base, } from "./definitions";
import { installOfflineHooks } from "./offline";
import { Config } from "./config";
import { backtrace, decodeString, nop } from "./util";
import { PiranhaMessage } from "./piranhamessage";

export function installHooks() {
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

    if (Config.offlineBattles)
        Interceptor.attach(base.add(Offsets.HomePageStartGame),
            {
                onEnter: function (args) {
                    args[3] = ptr(3);
                }
            });

    /*
    Interceptor.replace(base.add(Offsets.LogicCharacterServerHasUlti), new NativeCallback(function (a1 : NativePointer) {
        return 1;
    }, "bool", ["pointer"]));
    */

    /*
    Interceptor.attach(base.add(Offsets.NativeFontFormatString),
        {
            onEnter(args) {
                args[7] = ptr(1);
            },
        });
    */

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