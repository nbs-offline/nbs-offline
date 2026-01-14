import { Offsets } from "./offsets";
import {
  base,
  config,
  createMessageByType,
  messageManagerReceiveMessage,
  operator_new,
} from "./definitions";
import { PiranhaMessage } from "./piranhamessage";
import { getMessageManagerInstance } from "./util";
import { TeamManager } from "./teams/teammanager";
import { OwnHomeDataMessage } from "OwnHomeDataMessage";
import { writeConfig } from "./config";
import { PlayerProfileMessage } from "./packets/server/playerprofilemessage";
import { AvatarNameCheckRequestMessage } from "./packets/client/namechange/avatarnamecheckmessage";
import { ByteStream } from "./bytestream";
import { ChangeAvatarNameMessage } from "./packets/client/namechange/changeavatarnamemessage";
import { EndClientTurnMessage } from "./packets/client/endclientturnmessage";
import { SetSupportedCreatorMessage } from "./packets/client/setsupportedcreatormessage";
import { CreatePlayerMapMessage } from "./packets/client/mapmaker/createplayermapmessage";
import { PlayerMapsMessage } from "./packets/server/mapmaker/playermapsmessage";
import { DeletePlayerMapMessage } from "./packets/client/mapmaker/deleteplayermapmessage";
import { TeamCreateMessage } from "./packets/client/teams/teamcreatemessage";
import { Logger } from "./utility/logger";
import { LoginOkMessage } from "./packets/server/loginokmessage";
import { AskForBattleEndMessage } from "./packets/client/askforbattleendmessage";
import { SetCountryMessage } from "./packets/client/setcountrymessage";
import { UpdatePlayerMapMessage } from "./packets/client/mapmaker/updateplayermapmessage";
import { ChangePlayerMapNameMessage } from "./packets/client/mapmaker/changeplayermapnamemessage";

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
    let decodeOffset = message.readPointer().add(Offsets.Decode).readPointer();
    Logger.debug("Decode function for type", id + ":", decodeOffset.sub(base));
    let decode = new NativeFunction(decodeOffset, "void", ["pointer"]);
    decode(message);
    Logger.debug("Message decoded succesfully");
    messageManagerReceiveMessage(getMessageManagerInstance(), message);
    Logger.debug("Message received");
    return message;
  }

  static handleMessage(id: number, stream: ByteStream) {
    switch (id) {
      // ClientHelloMessage
      case 10100: {
        Messaging.sendOfflineMessage(20104, LoginOkMessage.encode());
        Messaging.sendOfflineMessage(24101, OwnHomeDataMessage.encode());
        if (config.teamExperiment) {
          TeamManager.createTeam();
        }
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
        if (config.teamExperiment) {
          TeamManager.createTeam();
        }
        break;
      }
      // AskForBattleEndMessage
      case 14110: {
        AskForBattleEndMessage.execute(AskForBattleEndMessage.decode(stream));
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
      case 12103: {
        UpdatePlayerMapMessage.execute(UpdatePlayerMapMessage.decode(stream));
        break;
      }
      case 12106: {
        ChangePlayerMapNameMessage.execute(ChangePlayerMapNameMessage.decode(stream))
      }
      case 12102: {
        Messaging.sendOfflineMessage(22102, PlayerMapsMessage.encode());
        break;
      }
      case 12101: {
        DeletePlayerMapMessage.execute(DeletePlayerMapMessage.decode(stream));
        break;
      }
      case 12998: {
        SetCountryMessage.execute(SetCountryMessage.decode(stream));
        break;
      }
      case 14350: {
        TeamCreateMessage.execute(TeamCreateMessage.decode(stream));
        break;
      }
    }
  }
}
