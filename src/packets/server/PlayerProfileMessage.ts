import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";
import { config, player } from "../../definitions.js";
import { PlayerDisplayData } from "../../playerdisplaydata.js";

export class PlayerProfileMessage {
  static encode(): number[] {
    let stream = new ByteStream([]);

    // PlayerProfile::encode
    stream.writeVlong(player.id[0], player.id[1]);
    stream.writeDataReference({ high: 16, low: config.favouriteBrawler });
    stream.writeDataReference({ high: 16, low: config.winstreakBrawler }); // winstreak brawler

    // HeroEntry::encode
    stream.writeVint(1); // hero entry

    stream.writeDataReference({ high: 16, low: 1 }); // character id
    stream.writeDataReference({ high: 0, low: -1 }); // skin equipped
    stream.writeVint(0); // trophies
    stream.writeVint(0); // highest trophies
    stream.writeVint(1); // highest season trophies
    stream.writeVint(0); // power level
    stream.writeVint(0); // mastery

    stream.writeVint(16);
    stream.writeVint(1);
    stream.writeVint(config.trioWins);
    stream.writeVint(8);
    stream.writeVint(config.soloWins);
    stream.writeVint(11);
    stream.writeVint(config.duoWins);
    stream.writeVint(29);
    stream.writeVint(player.trophies);
    stream.writeVint(4);
    stream.writeVint(player.highestTrophies);
    stream.writeVint(24);
    stream.writeVint(config.rankedHighest);
    stream.writeVint(25);
    stream.writeVint(config.rankedCurrent);
    stream.writeVint(20);
    stream.writeVint(config.fameCredits);
    stream.writeVint(27);
    stream.writeVint(config.creationDate);
    stream.writeVint(28);
    stream.writeVint(config.r35brawlers);
    stream.writeVint(9);
    stream.writeVint(config.highestRoboRumbleLvlPassed);
    stream.writeVint(12);
    stream.writeVint(config.highestBossFightLvlPassed);
    stream.writeVint(15);
    stream.writeVint(config.mostChallengeWins);
    stream.writeVint(16);
    stream.writeVint(config.highestRampageLvlPassed);
    stream.writeVint(18);
    stream.writeVint(config.highestSoloLeague);
    stream.writeVint(19);
    stream.writeVint(config.highestClubLeague);

    /* ***************************************** */
    let displaydata = new PlayerDisplayData(
      config.name,
      player.thumbnail,
      player.namecolor,
    );
    stream = displaydata.encode(stream);

    /* ***************************************** */
    stream.writeBoolean(false);
    stream.writeString("hello world");
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(config.winstreak); // max winstreak
    stream.writeDataReference({ high: 29, low: 0 }); // hero skin
    stream.writeDataReference({ high: 0, low: -1 }); // thumbnail 1
    stream.writeDataReference({ high: 0, low: -1 }); // thumbnail 2
    stream.writeDataReference({ high: 0, low: -1 }); // emote
    stream.writeDataReference({ high: 0, low: -1 }); // title

    stream.writeBoolean(false); // alliance header
    stream.writeDataReference({ high: 0, low: 0 }); // alliance role

    stream.writeVint(0);

    return stream.payload;
  }
}
