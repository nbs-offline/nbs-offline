import { Offsets } from "./offsets.js";
import { PiranhaMessage } from "./piranhamessage.js";
import {
  base,
  botNames,
  config,
  documentsDirectory,
  messagingSend,
  player,
  setBotNames,
  setText,
  setTextAndScaleIfNecessary,
  stringCtor,
} from "./definitions.js";
import { Messaging } from "./messaging.js";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage.js";
import {
  createStringObject,
  decodeString,
  getBotNames,
  getDocumentsDirectory,
  strPtr,
} from "./util.js";
import { BattleEndMessage } from "./packets/server/BattleEndMessage.js";
import { ByteStream } from "./bytestream.js";
import { AskForBattleEndMessage } from "./packets/client/AskForBattleEndMessage.js";
import { isAndroid } from "./platform.js";
import { PlayerProfileMessage } from "./packets/server/PlayerProfileMessage.js";
import { AvatarNameCheckRequestMessage } from "./packets/client/AvatarNameCheckRequestMessage.js";
import { ChangeAvatarNameMessage } from "./packets/client/ChangeAvatarNameMessage.js";
import { EndClientTurnMessage } from "./packets/client/EndClientTurnMessage.js";
import { writeConfig } from "./config.js";
import { SetSupportedCreatorMessage } from "./packets/client/SetSupportedCreatorMessage.js";
import { create } from "domain";
import { CreatePlayerMapMessage } from "./packets/client/CreatePlayerMapMessage.js";
import { PlayerMapsMessage } from "./packets/server/PlayerMapsMessage.js";
import { DeletePlayerMapMessage} from "./packets/client/DeletePlayerMapMessage.js"
import { TeamCreateMessage } from "./packets/client/teams/TeamCreateMessage.js"
import { TeamEntry } from "./teams/teamentry.js"
import { TeamMember } from "./teams/teammember.js"
import { Long } from "./long.js";

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

          if (type == 10100) {
            // ifs > switch
            Messaging.sendOfflineMessage(20104, []);
            Messaging.sendOfflineMessage(
              24101,
              OwnHomeDataMessage.encode(player),
            );
	    let entry = new TeamEntry(new Long(0, 1), 1, 0, 1);
            entry.teamMembers.push(new TeamMember(player, 11, true, 0, 1000));
	    console.log("entry");
	    let stream = new ByteStream([]);
	    Messaging.sendOfflineMessage(24124, entry.encode(stream).payload);
          } else if (type == 17750 || type == 12108) {
            // go home from offline practice
            if (config.tutorial) {
              config.tutorial = false;
              writeConfig(config);
            }
            Messaging.sendOfflineMessage(
              24101,
              OwnHomeDataMessage.encode(player),
            );  
          } else if (type == 14110) {
            // erm execute shouldn't have these args :nerd:
            AskForBattleEndMessage.execute(player, stream);
          } else if (type == 15081) {
            // get da profile
            Messaging.sendOfflineMessage(
              24113,
              PlayerProfileMessage.encode(player),
            );
          } else if (type == 14600) {
            // avatar name check request
            AvatarNameCheckRequestMessage.execute(player, stream);
          } else if (type == 10212) {
            // change avatar name message
            ChangeAvatarNameMessage.execute(player, stream);
          } else if (type == 14102) {
            EndClientTurnMessage.decodeAndExecute(player, stream);
          } else if (type == 18686) {
            SetSupportedCreatorMessage.decodeAndExecute(player, stream);
          } else if (type == 12100) {
            let map = CreatePlayerMapMessage.execute(player, stream);
          } else if (type == 12102) {
            Messaging.sendOfflineMessage(
              22102,
              PlayerMapsMessage.encode(player),
            );
          } else if (type == 12101) {
	    DeletePlayerMapMessage.execute(player, stream);
	  } else if (type == 14350) {
	    TeamCreateMessage.execute(player, stream);
	  }
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
}
