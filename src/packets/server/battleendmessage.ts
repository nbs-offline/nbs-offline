import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";
import { BattleEndData } from "../../battleenddata.js";
import { config } from "../../definitions.js";
import { PlayerDisplayData } from "../../playerdisplaydata.js";

// credits: https://github.com/risporce/BSDS/blob/v52/Classes/Packets/Server/Battle/BattleEndMessage.py
// updated to v59
export class BattleEndMessage {
  static encode(data: BattleEndData): number[] {
    let stream = new ByteStream([]);

    stream.writeLong(0, 1);
    stream.writeLong(0, 1);
    stream.writeVInt(data.gamemode);
    stream.writeVInt(data.rank);
    stream.writeVInt(0); // Tokens Gained (Gained Keys)
    stream.writeVInt(0); // Trophies Result (Metascore change)
    stream.writeVInt(0); // Power Play Points Gained (Pro League Points)
    stream.writeVInt(0); // Doubled Tokens (Double Keys)
    stream.writeVInt(0); // Double Token Event (Double Event Keys)
    stream.writeVInt(0); // Token Doubler Remaining (Double Keys Remaining)
    stream.writeVInt(0); // Game length in seconds
    stream.writeVInt(0); // Epic Win Power Play Points Gained (op Win Points)
    stream.writeVInt(0); // Championship Level Reached (CC Wins)
    stream.writeBoolean(false); // LogicGemOffer
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(true);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeVInt(-1);
    stream.writeBoolean(false);

    data.heroes.forEach((hero) => {
      stream.writeBoolean(hero.isPlayer);
      stream.writeBoolean(Boolean(hero.team));
      stream.writeBoolean(Boolean(hero.team));
      stream.writeByte(1);
      stream.writeDataReference(hero.id.high, hero.id.low);
      stream.writeByte(1);
      stream.writeVInt(0); // TODO: skin

      stream.writeByte(1);
      stream.writeVInt(1000); // TODO: trophies

      stream.writeByte(1);
      stream.writeVInt(11); // TODO: power level

      stream.writeByte(1);
      stream.writeVInt(0);

      stream.writeVInt(0);

      stream.writeBoolean(hero.isPlayer);
      if (hero.isPlayer) {
        stream.writeLong(config.id.high, config.id.low);
      }

      stream = new PlayerDisplayData(hero.name, 0, 0).encode(stream); // TODO: thumb and namecolor

      stream.writeBoolean(false); // club

      stream.writeByte(1);
      stream.writeVInt(5978);

      stream.writeByte(1);
      stream.writeVInt(0);

      stream.writeShort(5);
      stream.writeShort(3);
      stream.writeInt(27328);
      stream.writeInt(25659);
      stream.writeDataReference(0, 1);

      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeVInt(0);
    });

    stream.writeVInt(0); // xp entry
    stream.writeVInt(1);
    stream.writeVInt(0); // milestones progress
    stream.writeDataReference(0, -1);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeBoolean(false); // ranked match round state
    stream.writeVInt(0);
    stream.writeBoolean(false); // chronos text entry
    stream.writeVInt(0);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeBoolean(false);
    stream.writeBoolean(false); // kudosstatus
    stream.writeBoolean(false);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeBoolean(false);
    stream.writeVInt(0);
    stream.writeVInt(0);

    return stream.payload;
  }
}