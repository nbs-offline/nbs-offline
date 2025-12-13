import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import {
  base,
  botNames,
  config,
  homeModeGetInstance,
  setBotNames,
  setTextAndScaleIfNecessary,
  startGame,
} from "./definitions.js";
import { Messaging } from "./messaging.js";
import { createStringObject, decodeString, getBotNames } from "./util.js";
import { ByteStream } from "./bytestream.js";
import { isAndroid } from "./platform.js";
import { LogicData } from "./logicdata.js";

let progress: number;
let hasLoaded = false;
let firstTime = false;

export function installHooks() {
  Interceptor.attach(base.add(Offsets.DebuggerError), {
    onEnter(args) {
      console.log("ERROR:", args[0].readCString());
    },
  });

  Interceptor.attach(base.add(Offsets.DebuggerWarning), {
    onEnter(args) {
      console.log("WARN:", decodeString(args[0]));
    },
  });

  Interceptor.attach(base.add(Offsets.ServerConnectionUpdate), {
    onEnter: function (args) {
      if (args[0].readS32() == 0 && hasLoaded && firstTime) {
        console.log("resuming from updater");
        args[0].writeS32(1);
        firstTime = false;
      }
      args[0]
        .add(Process.pointerSize)
        .readPointer()
        .add(Offsets.HasConnectFailed)
        .writeU8(0);
      args[0]
        .add(Process.pointerSize)
        .readPointer()
        .add(Offsets.State)
        .writeInt(5);
    },
  });

  Interceptor.attach(base.add(Offsets.IsDev), {
    onLeave(retval) {
      retval.replace(ptr(1));
    },
  });

  Interceptor.attach(base.add(Offsets.IsDeveloperBuild), {
    onLeave(retval) {
      retval.replace(ptr(1));
    },
  });

  Interceptor.attach(base.add(Offsets.IsProd), {
    onLeave(retval) {
      retval.replace(ptr(0));
    },
  });

  Interceptor.attach(base.add(Offsets.MessageManagerReceiveMessage), {
    onLeave: function (retval) {
      retval.replace(ptr(1));
    },
  });

  Interceptor.attach(base.add(Offsets.StartGame), {
    onEnter: function (args) {
      args[3] = ptr(3);
      if (config.randomBotNames) {
        this.h = Interceptor.attach(base.add(Offsets.GetPlayerCount), {
          onLeave(retval) {
            setBotNames(getBotNames(retval.toInt32() - 1));
            console.log("Bot names:", botNames.toString());
          },
        });
      }
    },
    onLeave() {
      if (config.randomBotNames) {
        this.h.detach();
      }
    },
  });

  Interceptor.attach(base.add(Offsets.SendMessage), {
    onEnter(args) {
      PiranhaMessage.encode(args[1]);
      let messaging = args[0].add(Offsets.Messaging).readPointer();
      messaging.add(Offsets.State).writeInt(5);
    },
  });

  /*
  Interceptor.replace(
    base.add(Offsets.SendKeepAliveMessage),
    new NativeCallback(function () {}, "void", []),
  );
  */

  Interceptor.replace(
    base.add(Offsets.Send),
    new NativeCallback(
      function (self, message) {
        let type = PiranhaMessage.getMessageType(message);
        let length = PiranhaMessage.getEncodingLength(message);

        if (type === 10108) return 0;
        console.log("Type:", type);
        console.log("Length:", length);
        let payloadPtr = PiranhaMessage.getByteStream(message)
          .add(Offsets.PayloadPtr)
          .readPointer();
        let payload = payloadPtr.readByteArray(length);
        if (payload !== null) {
          let stream = new ByteStream(Array.from(new Uint8Array(payload)));
          console.log("Stream dump:", payload);
          Messaging.handleMessage(type, stream);
        }

        PiranhaMessage.destroyMessage(message);

        return 0;
      },
      "int",
      ["pointer", "pointer"],
    ),
  );

  // idk couldnt find on android
  /*
  Interceptor.attach(base.add(Offsets.ShouldShowChatButton), {
    onLeave(retval) {
      retval.replace(ptr(1)); // todo cfg opt
    },
  });
  */

  Interceptor.attach(base.add(Offsets.GetHelpfulHandState), {
    onLeave(retval) {
      retval.replace(ptr(-1));
    },
  });

  Interceptor.attach(base.add(Offsets.UpdateLoadingProgress), {
    onEnter(args) {
      this.textfield = args[0].add(Offsets.LoadingText).readPointer();
      this.goToAndStopFrameIndexHook = Interceptor.attach(
        base.add(Offsets.GotoAndStopFrameIndex),
        {
          onEnter(args) {
            progress = args[1].toInt32();
            if (progress == 99) hasLoaded = true;
          },
        },
      );
    },
    onLeave(retval) {
      if (config.customLoadingScreen) {
        let text = `[${progress}%] Loading game...`;
        setTextAndScaleIfNecessary(
          this.textfield,
          createStringObject(text),
          0,
          0,
        );
        this.goToAndStopFrameIndexHook.detach();
      }
    },
  });

  if (isAndroid && Process.arch == "arm64") {
    Interceptor.attach(base.add(Offsets.InitStateUpdateLoading), {
      onEnter() {
        const dlmgrinst = base
          .add(Offsets.DownloadManagerInstance)
          .readPointer();
        dlmgrinst.add(Offsets.Unk1).writeS32(6);
      },
    });

    Interceptor.replace(
      base.add(Offsets.UpdateChronosResources),
      new NativeCallback(function () {}, "void", []),
    );
  }

  Interceptor.attach(base.add(Offsets.StringTableGetString), {
    onEnter(args) {
      this.str = args[0].readUtf8String();
    },
    onLeave(retval) {
      if (config.randomBotNames && this.str.startsWith("TID_BOT_")) {
        let idx = this.str.split("TID_BOT_")[1] - 1;
        retval.replace(createStringObject(botNames[idx]));
      }
    },
  });

  Interceptor.replace(
    base.add(Offsets.GetPlayerDraftMapNumLimit), 
    new NativeCallback(() => {
      return config.draftMapLimit
    }, 'int', [])
  )

  Interceptor.replace(
    base.add(Offsets.ReceiveTeamGameStartingMessage),
    new NativeCallback(
      function () {
        console.log("trying to start");
        const homePage = homeModeGetInstance()
          .add(Offsets.HomeScreenInstance)
          .readPointer()
          .add(Offsets.HomePageInstance)
          .readPointer();
        startGame(
          homePage,
          ptr(0),
          new LogicData(15, 5).ptr,
          3,
          0,
          new LogicData(16, 0).ptr,
          0,
          new LogicData(29, 0).ptr,
          0,
        );
      },
      "void",
      [],
    ),
  );
}
