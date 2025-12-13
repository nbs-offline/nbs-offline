import { Offsets } from "./offsets.js";
import {
  base,
  config,
  createMessageByType,
  malloc,
  messageManagerReceiveMessage,
  operator_new,
} from "./definitions.js";
import { PiranhaMessage } from "./piranhamessage.js";
import { getMessageManagerInstance } from "./util.js";
import { TeamManager } from "./teams/teammanager.js";
import { OwnHomeDataMessage } from "./packets/server/OwnHomeDataMessage.js";
import { writeConfig } from "./config.js";
import { PlayerProfileMessage } from "./packets/server/PlayerProfileMessage.js";
import { AvatarNameCheckRequestMessage } from "./packets/client/namechange/AvatarNameCheckRequestMessage.js";
import { ByteStream } from "./bytestream.js";
import { ChangeAvatarNameMessage } from "./packets/client/namechange/ChangeAvatarNameMessage.js";
import { EndClientTurnMessage } from "./packets/client/EndClientTurnMessage.js";
import { SetSupportedCreatorMessage } from "./packets/client/SetSupportedCreatorMessage.js";
import { CreatePlayerMapMessage } from "./packets/client/mapmaker/CreatePlayerMapMessage.js";
import { PlayerMapsMessage } from "./packets/server/mapmaker/PlayerMapsMessage.js";
import { DeletePlayerMapMessage } from "./packets/client/mapmaker/DeletePlayerMapMessage.js";
import { TeamCreateMessage } from "./packets/client/teams/TeamCreateMessage.js";
import { TeamGameStartingMessage } from "./packets/server/TeamGameStartingMessage.js";

export class Messaging {
  static sendOfflineMessage(id: number, payload: number[]): NativePointer {
    let version = id == 20104 ? 1 : 0;
    const factory = Memory.alloc(512);
    factory.writePointer(base.add(Offsets.LogicLaserMessageFactory));
    let message = createMessageByType(factory, id);
    message.add(Offsets.Version).writeS32(version);
    const payloadLength = PiranhaMessage.getByteStream(message).add(
      Offsets.PayloadSize,
    );
    payloadLength.writeS32(payload.length);
    if (payload.length > 0) {
      let payloadPtr = operator_new(payload.length).writeByteArray(payload);
      PiranhaMessage.getByteStream(message)
        .add(Offsets.PayloadPtr)
        .writePointer(payloadPtr);
    }
    let decode = new NativeFunction(
      message.readPointer().add(Offsets.Decode).readPointer(),
      "void",
      ["pointer"],
    );
    decode(message);
    console.log("Message decoded succesfully");
    if (version == 1) {
      // login ok
      try {
        messageManagerReceiveMessage(getMessageManagerInstance(), message);
      } catch (e) {}
    } else {
      messageManagerReceiveMessage(getMessageManagerInstance(), message);
    }
    console.log("Message received");
    return message;
  }

  static handleMessage(id: number, stream: ByteStream) {
    switch (id) {
      // ClientHelloMessage
      case 10100: {
        Messaging.sendOfflineMessage(20104, []);
        Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
        TeamManager.createTeam();
        break;
      }
      // GoHomeFromOfflinePracticeMesage
      case 17750:
      // GoHomeFromMapEditorMessage
      case 12108: {
        if (config.tutorial) {
          config.tutorial = false;
          writeConfig(config);
        }
        Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
        TeamManager.createTeam();
        break;
      }
      // AskForBattleEndMessage
      case 14110: {
        // todo!
        break;
      }
      // GetPlayerProfileMessage
      case 15081: {
        // we dont need payload for now
        Messaging.sendOfflineMessage(24113, PlayerProfileMessage.encode());
        break;
      }
      // AvatarNameCheckRequestMessage
      case 14600: {
        AvatarNameCheckRequestMessage.execute(
          AvatarNameCheckRequestMessage.decode(stream),
        );
        break;
      }
      // ChangeAvatarNameMessage
      case 10212: {
        ChangeAvatarNameMessage.execute(ChangeAvatarNameMessage.decode(stream));
        break;
      }
      case 14102: {
        EndClientTurnMessage.execute(EndClientTurnMessage.decode(stream));
        break;
      }
      case 18686: {
        SetSupportedCreatorMessage.execute(
          SetSupportedCreatorMessage.decode(stream),
        );
        break;
      }
      case 12100: {
        CreatePlayerMapMessage.execute(CreatePlayerMapMessage.decode(stream));
        break;
      }
      case 12102: {
        Messaging.sendOfflineMessage(22102, PlayerMapsMessage.encode());
        break;
      }
      case 12101: {
        DeletePlayerMapMessage.execute(DeletePlayerMapMessage.decode(stream));
        break;
      }
      case 14350: {
        TeamCreateMessage.execute(TeamCreateMessage.decode(stream));
        break;
      }
      case 14355: {
        Messaging.sendOfflineMessage(24130, TeamGameStartingMessage.encode());
        break;
      }
    }
  }
}
