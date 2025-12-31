import { ByteStream } from "src/bytestream.js";
import { config } from "src/definitions.js";
import { calculateHighestTrophies, calculateTrophies } from "src/util.js";

export class OwnHomeDataMessage {
  static encode(): number[] {
    let stream = new ByteStream([]);

    stream.writeVInt(0); // timestamp
    stream.writeVInt(0);

    // LogicClientHome
    // LogicDailyData

    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(calculateTrophies(config.ownedBrawlers));
    stream.writeVInt(calculateHighestTrophies(config.ownedBrawlers));
    stream.writeVInt(calculateHighestTrophies(config.ownedBrawlers));
    stream.writeVInt(config.trophyRoadTier);
    stream.writeVInt(config.experience);

    stream.writeDataReference(28, config.thumbnail);
    stream.writeDataReference(43, config.namecolor);
    stream.writeVInt(38);
    for (let i = 0; i < 38; i++) stream.writeVInt(i);

    stream.writeVInt(0); // selected skins
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(config.ownedSkins.length);
    config.ownedSkins.forEach((x) => stream.writeDataReference(29, x));
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(calculateHighestTrophies(config.ownedBrawlers));
    stream.writeVInt(0);
    stream.writeVInt(2); // control mode
    stream.writeBoolean(false); // battle hints
    stream.writeVInt(config.tokenDoublers);
    stream.writeVInt(0); // bp season timer
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0); // time to next season

    stream.writeVInt(120);
    stream.writeVInt(200);

    stream.writeVInt(0); // forced drops

    stream.writeBoolean(true);
    stream.writeVInt(2);
    stream.writeVInt(2);
    stream.writeVInt(2);
    stream.writeVInt(0); // change name cost
    stream.writeVInt(0); // timer for next name change

    stream.writeVInt(0); // shop offers
    stream.writeVInt(0); // quests battle xp
    stream.writeVInt(0); // time left until xp reset

    stream.writeVInt(0);

    stream.writeVInt(1); // array
    stream.writeVInt(30);

    stream.writeByte(config.selectedBrawlers.length);
    for (const brawler of config.selectedBrawlers) {
      stream.writeDataReference(16, brawler);
    }
    stream.writeString(config.region);
    stream.writeString(config.supportedCreator);

    stream.writeVInt(23); // int values
    stream.writeVLong(config.rankedReputation, 41);
    stream.writeDataReference(2, 1);
    stream.writeDataReference(3, 0); /// tokens gained
    stream.writeDataReference(4, 0); // trophies gained
    stream.writeDataReference(6, 0); // demo account
    stream.writeDataReference(7, 0); // invites blocked
    stream.writeDataReference(8, 0); // star points gained
    stream.writeDataReference(9, 1); // shop star points
    stream.writeDataReference(10, 0); // power play trophies gained
    stream.writeDataReference(12, 1);
    stream.writeDataReference(14, 0); // coins gained
    stream.writeDataReference(15, 1); // social age
    stream.writeDataReference(16, 1);
    stream.writeDataReference(17, 0); // team chat muted
    stream.writeDataReference(18, 0); // esports button
    stream.writeDataReference(19, 0); // championship lives buy popup
    stream.writeDataReference(20, 0); // gems gained
    stream.writeDataReference(21, 1); // looking for team state
    stream.writeDataReference(22, 1);
    stream.writeDataReference(23, 0); // club trophies gained
    stream.writeDataReference(24, 1); // have already watched club league animation
    stream.writeDataReference(32447, 28);
    stream.writeDataReference(16, 5);

    stream.writeVInt(0); // cooldown entry

    // brawl pass
    // season data
    stream.writeVInt(1); // arr len
    stream.writeVInt(35 - 1);
    stream.writeVInt(config.passTokens);
    stream.writeBoolean(config.brawlPassPremium);
    stream.writeVInt(0);
    stream.writeBoolean(false);

    stream.writeBoolean(true);
    // bit list
    stream.writeInt(-1);
    stream.writeInt(-1);
    stream.writeInt(-1);
    stream.writeInt(-1);

    stream.writeBoolean(true);
    // bit list
    stream.writeInt(-1);
    stream.writeInt(-1);
    stream.writeInt(-1);
    stream.writeInt(-1);

    stream.writeBoolean(config.plus);

    stream.writeBoolean(true);
    // bit list
    stream.writeInt(-1);
    stream.writeInt(-1);
    stream.writeInt(-1);
    stream.writeInt(-1);

    // end of  bp

    // quests
    stream.writeBoolean(true);
    stream.writeVInt(0);
    stream.writeVInt(1); // 0
    stream.writeVInt(2); // 0
    stream.writeVInt(0);
    // end

    stream.writeBoolean(true);
    stream.writeVInt(
      config.ownedThumbnails.length + config.ownedPins.length + 1,
    );
    config.ownedThumbnails.forEach((x) => {
      stream.writeDataReference(28, x);
      stream.writeVInt(0);
    });
    config.ownedPins.forEach((x) => {
      stream.writeDataReference(52, x);
      stream.writeVInt(0);
    });
    stream.writeDataReference(28, 186);
    stream.writeVInt(0);

    stream.writeBoolean(false); // ranked data

    stream.writeInt(0);
    stream.writeVInt(0);
    stream.writeDataReference(16, config.favouriteBrawler);
    stream.writeBoolean(false); // LogicRewards
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    // daily data end
    // conf data

    stream.writeVInt(-1);

    // events
    // 52
    stream.writeVInt(40); // event slots
    for (let i = 0; i < 40; i++) stream.writeVInt(i);

    stream.writeVInt(config.events.length);

    for (const event of config.events) {
      stream.writeVInt(-1);
      stream.writeVInt(event.slot);
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeVInt(10);
      stream.writeDataReference(15, event.mapID);
      stream.writeVInt(-1);
      stream.writeVInt(2); // MapStatus

      stream.writeString("");
      stream.writeVInt(0);
      stream.writeVInt(0);

      if (
        [20, 21, 22, 23, 24, 35, 36].includes(event.slot) &&
        event.championShipInfo
      ) {
        stream.writeVInt(event.championShipInfo.maxWins);
      } else {
        stream.writeVInt(0);
      }

      stream.writeVInt(0); // modifiers
      stream.writeVInt(0); // wins
      stream.writeVInt(6);
      stream.writeBoolean(false); // MapMaker map structure array
      stream.writeVInt(0);
      stream.writeBoolean(false); // Power League array entry
      stream.writeVInt(0);
      stream.writeVInt(0);

      if (
        [20, 21, 22, 23, 24, 35, 36].includes(event.slot) &&
        event.championShipInfo
      ) {
        stream.writeBoolean(true); // chronosTextEntry
        stream.writeString(event.championShipInfo.chronosTextEntry);
        stream.writeVInt(0);
      } else {
        stream.writeBoolean(false);
      }

      stream.writeBoolean(false);
      stream.writeBoolean(false);

      if ([20, 21, 22, 23, 24].includes(event.slot) && event.championShipInfo) {
        stream.writeBoolean(true); // LogicGemOffer
        const offer = event.championShipInfo.logicGemOffer;
        stream.writeVInt(offer.id);
        stream.writeVInt(offer.amount);
        stream.writeDataReference(offer.csvID[0], offer.csvID[1]);
        stream.writeVInt(offer.skinID);
      } else {
        stream.writeBoolean(false);
      }

      stream.writeVInt(1);
      stream.writeVInt(6);

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
      stream.writeVInt(-1);
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeVInt(0);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
      stream.writeBoolean(false);
    }

    stream.writeVInt(0); // event data

    const brawlerUpgradeCost = [
      20, 35, 75, 140, 290, 480, 800, 1250, 1875, 2800,
    ];
    const shopCoinsPrice = [20, 50, 140, 280];
    const shopCoinsAmount = [300, 880, 2040, 4680];

    stream.writeVInt(brawlerUpgradeCost.length);
    for (const cost of brawlerUpgradeCost) {
      stream.writeVInt(cost);
    }
    stream.writeVInt(shopCoinsPrice.length);
    for (const price of shopCoinsPrice) {
      stream.writeVInt(price);
    }
    stream.writeVInt(shopCoinsAmount.length);
    for (const amount of shopCoinsAmount) {
      stream.writeVInt(amount);
    }

    stream.writeVInt(0); // release entry

    // int value entry
    stream.writeVInt(6);
    stream.writeDataReference(41000117, 1); // theme id
    stream.writeDataReference(89, 6);
    stream.writeDataReference(22, 0);
    stream.writeDataReference(36, 1);
    stream.writeDataReference(73, 1);
    stream.writeDataReference(16, 5);

    // idk which is new
    stream.writeVInt(0); // timed int value entry
    stream.writeVInt(0); // ad
    stream.writeVInt(0); // theme override entry

    // event asset list
    stream.writeVInt(1); // array
    stream.writeVInt(1);
    stream.writeBoolean(true);
    stream.writeString("1a1d6744f7dfb7bcfa54e3876c944b1da9d075db");
    stream.writeString(
      "/3f8dc547-1aed-4d85-81b0-32ead16f7474_collab_toystory.sc",
    );
    stream.writeVInt(83);
    stream.writeVInt(6);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    stream.writeVInt(0); // join club event entry
    stream.writeVInt(0); // daily fortune cookie
    stream.writeVInt(0); // chronos event asset list
    stream.writeVInt(0); // shop visual offer grouping entry
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    // logicconfdata end

    stream.writeLong(config.id.high, config.id.low);

    stream.writeVInt(0); // notification count
    stream.writeVInt(1);

    // gatcha drop
    stream.writeBoolean(false);
    stream.writeVInt(0);

    stream.writeVInt(0); // Roguelite completed brawler amounts
    stream.writeVInt(0); // arr

    // login calendar
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);

    stream.writeVInt(0); // gears

    stream.writeBoolean(true); // starr road
    stream.writeVInt(0); // arr
    stream.writeVInt(0); // arr
    stream.writeVInt(0); // actually data reference
    stream.writeVInt(1); // how many brawlers are being unlocked
    stream.writeDataReference(16, 0);
    stream.writeVInt(2); // credits needed
    stream.writeVInt(10000); // gem unlock price
    stream.writeVInt(0);
    stream.writeVInt(1); // current credits
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);

    // mastery
    stream.writeVInt(Object.keys(config.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      config.ownedBrawlers,
    )) {
      stream.writeVInt(brawlerData.masteryPoints); // Mastery Points
      stream.writeVInt(brawlerData.masteryClaimed); // Claimed Rewards
      stream.writeDataReference(16, Number(brawlerID)); // Brawler ID
    }

    // battle card; doesnt work in offline battles
    stream.writeDataReference(100, 1);
    stream.writeDataReference(28, -1); // Icon 1
    stream.writeDataReference(28, -1); // Icon 2
    stream.writeDataReference(52, -1); // Pin
    stream.writeDataReference(76, -1); // Title
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);
    stream.writeBoolean(false);

    stream.writeVInt(0); // brawler battle cards

    // random reward manager
    stream.writeVInt(14);
    for (let i = 0; i < 14; i++) {
      stream.writeDataReference(80, i);
      stream.writeVInt(-1);
      stream.writeVInt(0);
    }
    stream.writeVInt(0); // arr
    stream.writeInt(-1435281534);
    stream.writeVInt(0); // progression step in battles
    stream.writeVInt(0);
    stream.writeVInt(86400 * 24);
    stream.writeVInt(0); // arr
    stream.writeVInt(0);
    stream.writeVInt(0); // arr
    stream.writeVInt(0); // arr
    stream.writeVInt(0); // arr
    stream.writeVInt(0);
    stream.writeBoolean(false);

    stream.writeBoolean(false); // piggy
    stream.writeBoolean(false); // collab event data
    stream.writeBoolean(false); // special eent data
    stream.writeVInt(0); // last seen states from friendlist
    stream.writeBoolean(false); // contest event data

    // end LogicClientHome
    // LogicClientAvatar

    stream.writeVLong(config.id.high, config.id.low);
    stream.writeVLong(config.id.high, config.id.low);
    stream.writeVLong(config.id.high, config.id.low);
    stream.writeString(config.name);
    stream.writeBoolean(config.registered);
    stream.writeInt(-1);

    let count = 24;
    const unlockedBrawler = Object.values(config.ownedBrawlers).map(
      (i) => i.cardID,
    );

    stream.writeVInt(count);

    stream.writeVInt(unlockedBrawler.length + 3);
    for (const x of unlockedBrawler) {
      stream.writeDataReference(23, x);
      stream.writeVInt(-1);
      stream.writeVInt(1);
    }
    stream.writeDataReference(5, 8);
    stream.writeVInt(-1);
    stream.writeVInt(config.coins);
    stream.writeDataReference(5, 21);
    stream.writeVInt(-1);
    stream.writeVInt(0); // todo star road
    stream.writeDataReference(5, 23);
    stream.writeVInt(-1);
    stream.writeVInt(config.bling);

    stream.writeVInt(Object.keys(config.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      config.ownedBrawlers,
    )) {
      stream.writeDataReference(16, Number(brawlerID));
      stream.writeVInt(-1);
      stream.writeVInt(brawlerData.trophies);
    }

    stream.writeVInt(Object.keys(config.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      config.ownedBrawlers,
    )) {
      stream.writeDataReference(16, Number(brawlerID));
      stream.writeVInt(-1);
      stream.writeVInt(brawlerData.highestTrophies);
    }

    stream.writeVInt(0);

    stream.writeVInt(0); // hero power

    stream.writeVInt(Object.keys(config.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      config.ownedBrawlers,
    )) {
      stream.writeDataReference(16, Number(brawlerID));
      stream.writeVInt(-1);
      stream.writeVInt(brawlerData.powerlevel - 1);
    }

    stream.writeVInt(0); // hero star power gadget and hyper

    stream.writeVInt(Object.keys(config.ownedBrawlers).length);
    for (const [brawlerID, brawlerData] of Object.entries(
      config.ownedBrawlers,
    )) {
      stream.writeDataReference(16, Number(brawlerID));
      stream.writeVInt(-1);
      stream.writeVInt(brawlerData.state);
    }

    for (let i = 0; i < count - 7; i++) {
      stream.writeVInt(0);
    }

    stream.writeVInt(config.gems); // Diamonds
    stream.writeVInt(config.gems); // Free Diamonds
    stream.writeVInt(config.experienceLevel); // Player Level
    stream.writeVInt(100);
    stream.writeVInt(0); // CumulativePurchasedDiamonds / Level Tier
    stream.writeVInt(100); // Battle Count
    stream.writeVInt(10); // WinCount
    stream.writeVInt(80); // LoseCount
    stream.writeVInt(50); // WinLoseStreak
    stream.writeVInt(20); // NpcWinCount
    stream.writeVInt(0); // NpcLoseCount
    stream.writeVInt(config.tutorial ? 0 : 2); // TutorialState
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeVInt(0);
    stream.writeString("");
    stream.writeVInt(0);
    stream.writeVInt(0);

    return stream.payload;
  }
}
