import { PlayerDisplayData } from "../playerdisplaydata.js";
import { Player } from "../player.js";
import { ByteStream } from "../bytestream.js";
import { config } from "../definitions.js";

export class TeamMember {
  isOwner = true;
  state = 0;
  playerDisplayData: PlayerDisplayData;
  characterID = 0;
  ready = false;

  constructor(isOwner: boolean, state: number) {
    this.isOwner = isOwner;
    this.state = state;
    this.characterID = config.selectedBrawlers[0];
    this.playerDisplayData = new PlayerDisplayData(
      config.name,
      config.thumbnail,
      config.namecolor,
    );
  }

  encode(stream: ByteStream): ByteStream {
    stream.writeBoolean(this.isOwner);
    stream.writeLong(0, 1); // acc id
    stream.writeDataReference({ high: 16, low: this.characterID });
    stream.writeDataReference({ high: 29, low: 0 }); // skin
    stream.writeVint(1000);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(this.state);
    stream.writeBoolean(this.ready);
    stream.writeVint(0); // team index
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream = this.playerDisplayData.encode(stream);
    /*
    stream.writeDataReference({ high: 23, low: 0 }); // gear 1
    stream.writeDataReference({ high: 23, low: 1 }); // gear 2
    stream.writeDataReference({ high: 62, low: 0 }); // star power
    stream.writeDataReference({ high: 62, low: 0 }); // gadget
    */
    for (let i = 0; i < 5; i++) {
      stream.writeVint(0); // gears, starpower, gadget and hypercharge respectfully
    }
    stream.writeVint(0);
    return stream;
  }
}
