import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { config, player } from "../../definitions.js";

export class OwnHomeDataMessage {
  static encode(): number[] {
    let stream = new ByteStream([]);
    const currentTime = Date.now() / 1000 + 3600 * 4;
    console.log("Encoding OHD");

    stream.writeVint(currentTime);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);

    stream.writeVint(player.trophies);
    stream.writeVint(player.highestTrophies);
    stream.writeVint(player.highestTrophies);
    stream.writeVint(player.trophyRoadTier);
    stream.writeVint(player.xp);

    stream.writeDataReference({ high: 28, low: player.thumbnail });
    stream.writeDataReference({ high: 43, low: player.namecolor });
    stream.writeVint(26);
    for (let i = 0; i < 26; i++) stream.writeVint(i);

    stream.writeVint(0); // selected skins
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(player.ownedSkins.length);
    player.ownedSkins.forEach((x) =>
      stream.writeDataReference({ high: 29, low: x }),
    );
    stream.writeVint(1080);
    for (let i = 0; i < 1080; i++)
      stream.writeDataReference({ high: 29, low: i });
    stream.writeVint(0);
    stream.writeVint(0); // e
    stream.writeVint(player.highestTrophies);
    stream.writeVint(0);
    stream.writeVint(2);
    stream.writeBoolean(true);
    stream.writeVint(player.tokenDoublers);
    stream.writeVint(335442);
    stream.writeVint(1001442);
    stream.writeVint(5778642);
    stream.writeVint(0);

    stream.writeVint(120);
    stream.writeVint(200);
    stream.writeVint(0);

    stream.writeBoolean(true);
    stream.writeVint(2);
    stream.writeVint(2);
    stream.writeVint(2);
    stream.writeVint(0);
    stream.writeVint(0);

    stream.writeVint(0); // shop offers
    stream.writeVint(20);
    stream.writeVint(1428);

    stream.writeVint(0);

    stream.writeVint(1);
    stream.writeVint(30);

    stream.writeByte(player.selectedBrawlers.length);
    for (const brawler of player.selectedBrawlers) {
      stream.writeDataReference({ high: 16, low: brawler });
    }
    stream.writeString(player.region);
    stream.writeString(config.supportedCreator);

    stream.writeVint(23); // int values
    stream.writeVlong(config.rankedReputation, 41);
    stream.writeDataReference({ high: 2, low: 1 });
    stream.writeDataReference({ high: 3, low: 0 }); /// tokens gained
    stream.writeDataReference({ high: 4, low: 0 }); // trophies gained
    stream.writeDataReference({ high: 6, low: 0 }); // demo account
    stream.writeDataReference({ high: 7, low: 0 }); // invites blocked
    stream.writeDataReference({ high: 8, low: 0 }); // star points gained
    stream.writeDataReference({ high: 9, low: 1 }); // shop star points
    stream.writeDataReference({ high: 10, low: 0 }); // power play trophies gained
    stream.writeDataReference({ high: 12, low: 1 });
    stream.writeDataReference({ high: 14, low: 0 }); // coins gained
    stream.writeDataReference({ high: 15, low: 1 }); // social age
    stream.writeDataReference({ high: 16, low: 1 });
    stream.writeDataReference({ high: 17, low: 0 }); // team chat muted
    stream.writeDataReference({ high: 18, low: 0 }); // esports button
    stream.writeDataReference({ high: 19, low: 0 }); // championship lives buy popup
    stream.writeDataReference({ high: 20, low: 0 }); // gems gained
    stream.writeDataReference({ high: 21, low: 1 }); // looking for team state
    stream.writeDataReference({ high: 22, low: 1 });
    stream.writeDataReference({ high: 23, low: 0 }); // club trophies gained
    stream.writeDataReference({ high: 24, low: 1 }); // have already watched club league animation
    stream.writeDataReference({ high: 32447, low: 28 });
    stream.writeDataReference({ high: 16, low: 5 });

    stream.writeVint(0);

    // brawl pass
    let pass32LVL = 0;
    let pass64LVL = 0;
    let pass96LVL = 0;

    let free32LVL = 0;
    let free64LVL = 0;
    let free96LVL = 0;

    for (const level of player.brawlPassFreeLevel) {
      if (level < 30) {
        free32LVL += 2 ** (level + 2);
      }
      if (level > 30) {
        free64LVL += 2 ** (level - 30);
      }
      if (level > 61) {
        free96LVL += 1 ** (level - 61);
      }
    }

    for (const level of player.brawlPassLevel) {
      if (level < 30) {
        pass32LVL += 2 ** (level + 2);
      }
      if (level > 29) {
        pass64LVL += 2 ** (level - 30);
      }
      if (level > 60) {
        pass96LVL += 1 ** (level - 61);
      }
    }

    // season data
    stream.writeVint(1);
    stream.writeVint(34); // season
    stream.writeVint(player.passTokens);
    stream.writeBoolean(player.brawlPassActive);
    stream.writeVint(0);
    stream.writeBoolean(false);

    stream.writeBoolean(true);
    stream.writeInt(pass32LVL);
    stream.writeInt(pass64LVL);
    stream.writeInt(pass96LVL);
    stream.writeInt(0);

    stream.writeBoolean(true);
    stream.writeInt(free32LVL);
    stream.writeInt(free64LVL);
    stream.writeInt(free96LVL);
    stream.writeInt(0);

    stream.writeBoolean(player.brawlPassPlusActive);
    stream.writeBoolean(true);
    stream.writeInt(0);
    stream.writeInt(0);
    stream.writeInt(0);
    stream.writeInt(0);

    stream.writeBoolean(true);
    stream.writeVint(0);
    stream.writeVint(1);
    stream.writeVint(2);
    stream.writeVint(0);

    stream.writeBoolean(true);
    stream.writeVint(
      player.ownedThumbnails.length + player.ownedPins.length + 1,
    );
    player.ownedThumbnails.forEach((x) => {
      stream.writeDataReference({ high: 28, low: x });
      stream.writeVint(0);
    });
    player.ownedPins.forEach((x) => {
      stream.writeDataReference({ high: 52, low: x });
      stream.writeVint(0);
    });
    stream.writeDataReference({ high: 28, low: 186 });
    stream.writeVint(0);

    stream.writeBoolean(false); // powerleague data

    stream.writeInt(0);
    stream.writeVint(0);
    stream.writeDataReference({ high: 16, low: player.favouriteBrawler });
    stream.writeBoolean(false);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);

    // daily data end
    // conf data

    stream.writeVint(-1);

    // events
    stream.writeVint(40);
    for (let i = 0; i < 40; i++) stream.writeVint(i);

    stream.writeVint(config.events.length);

    for (const event of config.events) {
      stream.writeVint(-1);
      stream.writeVint(event.slot);
      stream.writeVint(event.slot);
      stream.writeVint(0);
      stream.writeVint(0);
      stream.writeVint(10);
      stream.writeDataReference({ high: 15, low: event.mapID });
      stream.writeVint(-1);
      stream.writeVint(2); // MapStatus
      stream.writeString("");
      stream.writeVint(0);
      stream.writeVint(0);

      if (
        [20, 21, 22, 23, 24, 35, 36].includes(event.slot) &&
        event.championShipInfo
      ) {
        stream.writeVint(event.championShipInfo.maxWins);
      } else {
        stream.writeVint(0);
      }

      stream.writeVint(0); // Modifiers
      stream.writeVint(0); // Wins
      stream.writeVint(6);
      stream.writeBoolean(false); // MapMaker map structure array
      stream.writeVint(0);
      stream.writeBoolean(false); // Power League array entry
      stream.writeVint(0);
      stream.writeVint(0);

      if (
        [20, 21, 22, 23, 24, 35, 36].includes(event.slot) &&
        event.championShipInfo
      ) {
        stream.writeBoolean(true); // chronosTextEntry
        stream.writeString(event.championShipInfo.chronosTextEntry);
        stream.writeVint(0);
      } else {
        stream.writeBoolean(false);
      }

      stream.writeBoolean(false);
      stream.writeBoolean(false);

      if ([20, 21, 22, 23, 24].includes(event.slot) && event.championShipInfo) {
        stream.writeBoolean(true); // LogicGemOffer
        const offer = event.championShipInfo.logicGemOffer;
        stream.writeVint(offer.id);
        stream.writeVint(offer.amount);
        stream.writeDataReference({
          high: offer.csvID[0],
          low: offer.csvID[1],
        });
        stream.writeVint(offer.skinID);
      } else {
        stream.writeBoolean(false);
      }

      stream.writeVint(1);
      stream.writeVint(6);

      if (
        [20, 21, 22, 23, 24, 35, 36].includes(event.slot) &&
        event.championShipInfo
      ) {
        stream.writeBoolean(true); // ChronosFileEntry
        const entry = event.championShipInfo.chronosFileEntry;
        stream.writeString(entry.scName);
        stream.writeString(entry.scFile);
      }

      stream.writeBoolean(false); // ChoronosFileEntry::encode
      stream.writeBoolean(false);
      stream.writeVint(-1);
      stream.writeVint(0);
      stream.writeVint(0);
      stream.writeVint(0);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
    }

    stream.writeVint(0);

    const brawlerUpgradeCost = [
      20, 35, 75, 140, 290, 480, 800, 1250, 1875, 2800,
    ];
    const shopCoinsPrice = [20, 50, 140, 280];
    const shopCoinsAmount = [300, 880, 2040, 4680];

    stream.writeVint(brawlerUpgradeCost.length);
    for (const cost of brawlerUpgradeCost) {
      stream.writeVint(cost);
    }
    stream.writeVint(shopCoinsPrice.length);
    for (const price of shopCoinsPrice) {
      stream.writeVint(price);
    }
    stream.writeVint(shopCoinsAmount.length);
    for (const amount of shopCoinsAmount) {
      stream.writeVint(amount);
    }

    stream.writeVint(0);

    // int value entry
    stream.writeVint(6);
    stream.writeDataReference({ high: 41000117, low: 1 }); // theme id
    stream.writeDataReference({ high: 89, low: 6 });
    stream.writeDataReference({ high: 22, low: 0 });
    stream.writeDataReference({ high: 36, low: 1 });
    stream.writeDataReference({ high: 73, low: 1 });
    stream.writeDataReference({ high: 16, low: 5 });

    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);

    stream.writeVint(1);
    stream.writeVint(1);
    stream.writeBoolean(true);
    stream.writeString("1a1d6744f7dfb7bcfa54e3876c944b1da9d075db");
    stream.writeString(
      "/3f8dc547-1aed-4d85-81b0-32ead16f7474_collab_toystory.sc",
    );
    stream.writeVint(83);
    stream.writeVint(6);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);

    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);

    // logicconfdata end

    stream.writeLong(player.id[0], player.id[1]);

    stream.writeVint(0); // notification count

    stream.writeVint(1);
    stream.writeBoolean(false);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeVint(0);

    stream.writeBoolean(true); // starr road

    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(1); // todo: unlocking brawler
    stream.writeDataReference({ high: 16, low: 0 });
    stream.writeVint(2); // credits needed
    stream.writeVint(10000); // gem unlock price
    stream.writeVint(0);
    stream.writeVint(1); // current credits
    stream.writeVint(0);
    stream.writeVint(0);

    stream.writeVint(0);

    stream.writeVint(0);
    stream.writeVint(0);

    // mastery
    stream.writeVint(Object.keys(player.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      player.ownedBrawlers,
    )) {
      stream.writeVint(brawlerData.masteryPoints); // Mastery Points
      stream.writeVint(brawlerData.masteryClaimed); // Claimed Rewards
      stream.writeDataReference({ high: 16, low: Number(brawlerID) }); // Brawler ID
    }

    // battle card
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);

    stream.writeVint(0); // brawler battle cards

    // starr drop data
    stream.writeVint(14);
    for (let i = 0; i < 14; i++) {
      stream.writeDataReference({ high: 80, low: i });
      stream.writeVint(-1);
      stream.writeVint(0);
    }
    stream.writeVint(0);
    stream.writeInt(-1435281534);
    stream.writeVint(0); // progression step in battles
    stream.writeVint(0);
    stream.writeVint(86400 * 24);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeBoolean(false);

    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeVint(0);
    stream.writeBoolean(false);

    // end LogicClientHome

    stream.writeVlong(player.id[0], player.id[1]);
    stream.writeVlong(player.id[0], player.id[1]);
    stream.writeVlong(player.id[0], player.id[1]);
    stream.writeString(config.name);
    stream.writeBoolean(config.registered);
    stream.writeInt(-1);

    stream.writeVint(24);
    const unlockedBrawler = Object.values(player.ownedBrawlers).map(
      (i) => i.cardID,
    );
    stream.writeVint(unlockedBrawler.length + 3);
    for (const x of unlockedBrawler) {
      stream.writeDataReference({ high: 23, low: x });
      stream.writeVint(-1);
      stream.writeVint(1);
    }

    stream.writeDataReference({ high: 5, low: 8 });
    stream.writeVint(-1);
    stream.writeVint(player.coins);

    stream.writeDataReference({ high: 5, low: 21 });
    stream.writeVint(-1);
    stream.writeVint(0); // todo star road

    stream.writeDataReference({ high: 5, low: 23 });
    stream.writeVint(-1);
    stream.writeVint(player.bling);

    stream.writeVint(Object.keys(player.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      player.ownedBrawlers,
    )) {
      stream.writeDataReference({ high: 16, low: Number(brawlerID) });
      stream.writeVint(-1);
      stream.writeVint(brawlerData.trophies);
    }

    stream.writeVint(Object.keys(player.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      player.ownedBrawlers,
    )) {
      stream.writeDataReference({ high: 16, low: Number(brawlerID) });
      stream.writeVint(-1);
      stream.writeVint(brawlerData.highestTrophies);
    }

    stream.writeVint(0);

    stream.writeVint(0); // hero power

    stream.writeVint(Object.keys(player.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      player.ownedBrawlers,
    )) {
      stream.writeDataReference({ high: 16, low: Number(brawlerID) });
      stream.writeVint(-1);
      stream.writeVint(brawlerData.powerlevel - 1);
    }

    stream.writeVint(0); // hero star power gadget and hyper

    stream.writeVint(Object.keys(player.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      player.ownedBrawlers,
    )) {
      stream.writeDataReference({ high: 16, low: Number(brawlerID) });
      stream.writeVint(-1);
      stream.writeVint(brawlerData.state);
    }

    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeVint(0);

    stream.writeVint(player.gems); // Diamonds
    stream.writeVint(player.gems); // Free Diamonds
    stream.writeVint(player.level); // Player Level
    stream.writeVint(100);
    stream.writeVint(0); // CumulativePurchasedDiamonds / Level Tier
    stream.writeVint(100); // Battle Count
    stream.writeVint(10); // WinCount
    stream.writeVint(80); // LoseCount
    stream.writeVint(50); // WinLoseStreak
    stream.writeVint(20); // NpcWinCount
    stream.writeVint(0); // NpcLoseCount
    stream.writeVint(config.tutorial ? 0 : 2); // TutorialState
    stream.writeVint(12);
    stream.writeVint(0);
    stream.writeVint(0);
    stream.writeString("");
    stream.writeVint(0);
    stream.writeVint(0);

    return stream.payload;
  }
}
