import { ByteStream } from "../../bytestream.js";
import { BattleEndData } from "../../battleenddata.js";
import { config } from "../../definitions.js";
import { PlayerDisplayData } from "src/playerdisplaydata.js";

// credits: https://github.com/risporce/BSDS/blob/v52/Classes/Packets/Server/Battle/BattleEndMessage.py
// updated to v59
export class BattleEndMessage {
  static encode(data: BattleEndData): number[] {
    let stream = new ByteStream([]);

    stream.writeLong(0, 1);
    stream.writeLong(0, 1);
    stream.writeVInt(2); // Game mode (data.gamemode)
    stream.writeVInt(0); // Result (Victory/Defeat/Draw/Rank Score) (data.rank)
    stream.writeVInt(0); // Tokens Gained (Gained Keys)
    stream.writeVInt(0); // Trophies Result (Metascore change)
    stream.writeVInt(0); // Power Play Points Gained (Pro League Points)
    stream.writeVInt(0); // Doubled Tokens (Double Keys)
    stream.writeVInt(0); // Double Token Event (Double Event Keys)
    stream.writeVInt(0); // Token Doubler Remaining (Double Keys Remaining)
    stream.writeVInt(0); // Game length in seconds
    // Epic Win Power Play Points Gained (op Win Points)
    stream.writeVInt(0); // Championship Level Reached (CC Wins)
    // One of ^ was removed since v52

    stream.writeBoolean(false); // Gem offer

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
    stream.writeBoolean(true); // IsPvP
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeVInt(-1); // Challenge type
    stream.writeBoolean(false);

    stream.writeVInt(data.heroes.length);
    data.heroes.forEach(hero => {
      stream.writeBoolean(hero.isPlayer);
      stream.writeBoolean(Boolean(hero.team));
      stream.writeBoolean(false);

      stream.writeVInt(1);
      stream.writeDataReference(hero.id.high, hero.id.low);

      stream.writeVInt(1);
      stream.writeDataReference(hero.skinID.high, hero.skinID.low)

      stream.writeVInt(1);
      stream.writeVInt(hero.isPlayer ? 1000 : 0); // TODO: Real trophies

      stream.writeVInt(1);
      stream.writeVInt(hero.isPlayer ? 11 : 1); // TODO: Real power level

      stream.writeVInt(1);
      stream.writeVInt(0);
  
      stream.writeVInt(0);
  
      stream.writeBoolean(hero.isPlayer);
      if (hero.isPlayer) {
        stream.writeLong(config.id.high, config.id.low);
      }

      // TODO: Thumb and name colour
      stream = new PlayerDisplayData(hero.name, 0, 0).encode(stream);

      stream.writeBoolean(false); // In club (todo)

      stream.writeVInt(0);

      stream.writeVInt(0);

      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeInt(0);
      stream.writeInt(0);
      stream.writeDataReference(0, 1);
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeVInt(0);
    });

    stream.writeVInt(0); // xp entry

    stream.writeVInt(0); // milestones progress

    stream.writeVInt(1);
    //sub
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeDataReference(0, 1);
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
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeBoolean(false);

    return stream.payload;
  }
}
