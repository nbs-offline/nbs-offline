import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { encodeEvents } from "../../events.js";

export class OwnHomeDataMessage {
    static encode(player: Player): number[] {
        let stream = new ByteStream([]);
        console.log("Encoding OHD");

        stream.writeVint(0); // Timestamp
        stream.writeVint(0); // Timestamp

        // LogicDailyData::encode
        stream.writeVint(0); // Timestamp
        stream.writeVint(0); // Timer For Region Change

        stream.writeVint(player.trophies);
        stream.writeVint(player.highestTrophies); 
        stream.writeVint(player.highestTrophies);
        stream.writeVint(player.trophyRoadTier);
        stream.writeVint(player.level);
        stream.writeDataReference({ high: 28, low: player.thumbnail });
        stream.writeDataReference({ high: 43, low: player.namecolor });

        stream.writeVint(26);
        for (let x = 0; x < 26; x++) {
            stream.writeVint(x);
        }

        stream.writeVint(0)

        stream.writeVint(0);

        stream.writeVint(0);

        stream.writeVint(0);

        stream.writeVint(0);

        stream.writeVint(0);

        stream.writeVint(0); // Leaderboard Region |
        stream.writeVint(70000); // Trophy Road Highest Trophies
        stream.writeVint(0); // Tokens Used in Battles
        stream.writeVint(1); // Control Mode
        stream.writeBoolean(true); // Battle Hints
        stream.writeVint(19500); // Tokens Doubler
        stream.writeVint(111111); // Power Play Timer
        stream.writeVint(1375134); // Trophies Season Reset Timer
        stream.writeVint(0); // Pro Pass Season Timer
        stream.writeVint(1375134); // Brawl Pass Season Timer

        stream.writeVint(200); // Starpower Drop
        stream.writeVint(200); // Gadget Drop
        stream.writeVint(0); // Rarity Count

        stream.writeBoolean(true);
        stream.writeVint(2); // Token Doubler New Tag State
        stream.writeVint(2); // Event Tickets New Tag State
        stream.writeVint(2); // Coin Packs New Tag State
        stream.writeVint(0); // Change Name Cost
        stream.writeVint(0); // Timer For the Next Name Change
        stream.writeVint(0); // ?

        // LogicOfferBundle::encode
        stream.writeVint(0); // Shop Offers Count
        stream.writeVint(20);
        stream.writeVint(1428);

        stream.writeVint(0);

        stream.writeVint(1);
        stream.writeVint(30);

        stream.writeByte(1); // Selected Brawler
        stream.writeDataReference({ high: 16, low: 1 })

        stream.writeString(player.region); // Location
        stream.writeString(player.supportedCreator); // Supported Content Creator

        // IntValueEntry::encode
        stream.writeVint(15);
        stream.writeDataReference({ high: 2, low: 1 }); // Unknown
        stream.writeDataReference({ high: 9, low: 1 }); // Show Star Points
        stream.writeDataReference({ high: 10, low: 0 }); // Power Play Trophies Gained
        stream.writeDataReference({ high: 12, low: 1 }); // Unknown
        stream.writeDataReference({ high: 14, low: 0 }); // Coins Gained
        stream.writeDataReference({ high: 16, low: 1 });
        stream.writeDataReference({ high: 17, low: 0 }); // Team Chat Muted
        stream.writeDataReference({ high: 18, low: 1 }); // Esport Button
        stream.writeDataReference({ high: 19, low: 0 }); // Champion Ship Lives Buy Popup
        stream.writeDataReference({ high: 21, low: 1 }); // Looking For Team State
        stream.writeDataReference({ high: 22, low: 1 });
        stream.writeDataReference({ high: 23, low: 0 }); // Club Trophies Gained
        stream.writeDataReference({ high: 24, low: 1 }); // Have already watched club league stupid animation
        stream.writeDataReference({ high: 32447, low: 28 });
        stream.writeDataReference({ high: 16, low: 5 });
        // Added IntValueEntry::encode

        // CooldownEntry::encode
        stream.writeVint(0); // CooldownEntry::encode
        // Added CooldownEntry::encode

        // BrawlPassSeasonData::encode
        stream.writeVint(0);
        // Added BrawlPassSeasonData::encode

        // LogicQuests::encode
        stream.writeBoolean(true);
        stream.writeVint(0); // Quests Count
        stream.writeVint(0); // ?
        stream.writeVint(0); // ?
        stream.writeVint(0); // ?
        // Added LogicQuests::encode

        // VanityItems::encode
        stream.writeBoolean(true); // Vanity items
        stream.writeVint(0)
        // Added VanityItems::encode

        // LogicPlayerRankedSeasonData::encode
        stream.writeBoolean(false); // LogicPlayerRankedSeasonData::encode

        stream.writeInt(0);
        stream.writeVint(0);
        stream.writeDataReference({ high: 16, low: 1 }) // Favorite Brawler
        stream.writeBoolean(false); // LogicRewards::encode
        stream.writeVint(-1);
        stream.writeVint(0);
        stream.writeVint(832099);
        stream.writeVint(1616899);
        stream.writeVint(10659101);
        stream.writeVint(0);

        // CompetitivePassSeasonData::encode
        stream.writeVint(0);
        stream.writeVint(0); // Pro Pass

        stream.writeDataReference({ high: 2, low: 333 })
        stream.writeDataReference({ high: 2, low: 347 })
        stream.writeDataReference({ high: 2, low: 334 })
        stream.writeDataReference({ high: 2, low: 335 })

        stream.writeBoolean(false);

        // Added EsportsButtonStateData::encode
        stream.writeDataReference({ high: 2, low: 351 })
        stream.writeVint(770); // LogicDailyData::encode
        stream.writeBoolean(false);
        stream.writeBoolean(false);

        stream.writeVint(2025074);

        stream.writeVint(52); // event slots
        for (let eventID = 0; eventID < 52; eventID++) {
            stream.writeVint(eventID);
        }

        stream.writeVint(18); // event count
        encodeEvents(stream);
        stream.writeVint(0);
        stream.writeVint(0);

        stream.writeVint(0); // int list
        stream.writeVint(0); // int list 
        stream.writeVint(0); // int list

        stream.writeVint(0); // release entry array
        // conf data int vals
        stream.writeVint(6);
        for (let i = 0; i < 1; i++) {
            stream.writeDataReference({ high: 41000140, low: 1 }) // ThemeID
            stream.writeDataReference({ high: 89, low: 6 })
            stream.writeDataReference({ high: 22, low: 0 })
            stream.writeDataReference({ high: 36, low: 1 })
            stream.writeDataReference({ high: 73, low: 1 })
            stream.writeDataReference({ high: 16, low: 5 })
        }

        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])

        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])

        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])

        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])

        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])
        stream.writeVint(0); // Added TimedIntValueEntry array count (a1[45])

        stream.writeLong({ high: 0, low: 1 });
        stream.writeVint(0); // Array

        stream.writeVint(1);
        stream.writeBoolean(false); // LogicGatchaDrop::encode
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeBoolean(false); // LogicLoginCalendar::encode
        stream.writeBoolean(false); // Added LogicLoginCalendar::encode
        stream.writeBoolean(false); // Added LogicLoginCalendar::encode
        stream.writeBoolean(false); // Added LogicLoginCalendar::encode

        // LogicHeroGears::encode
        stream.writeVint(0); // Count
        // Added LogicHeroGears::encode

        stream.writeBoolean(false); // LogicBrawlerRecruitRoad::encode
        // Added LogicBrawlerRecruitRoad::encode

        // LogicMasteries::encode
        stream.writeVint(0); // LogicMasteries::encode
        // Added LogicMasteries::encode

        // LogicBattleIntro::encode
        // Added LogicHeroBattleIntro::encode
        stream.writeDataReference({ high: 100, low: 1 })
        stream.writeDataReference({ high: 28, low: -1 }) // Icon 1
        stream.writeDataReference({ high: 28, low: -1 }) // Icon 2
        stream.writeDataReference({ high: 52, low: -1 }) // Pin
        stream.writeDataReference({ high: 76, low: -1 }) // Title
        stream.writeDataReference({ high: 0, low: -1 });
        stream.writeBoolean(false);
        stream.writeBoolean(false);
        stream.writeBoolean(false);
        stream.writeBoolean(false);
        stream.writeBoolean(false);
        stream.writeVint(0); // Count
        // Added LogicHeroBattleIntro::encode
        // Added LogicBattleIntro::encode

        stream.writeVint(0)
        stream.writeVint(0)
        stream.writeInt(-1435281534)
        stream.writeVint(0)
        stream.writeVint(0)
        stream.writeVint(86400 * 24)
        stream.writeVint(0)
        stream.writeVint(0)
        stream.writeVint(0)
        stream.writeVint(0)
        stream.writeVint(0)
        stream.writeVint(0)
        stream.writeBoolean(false)

        stream.writeBoolean(false); // LogicPlayerAlliancePiggyBankData::encode
        stream.writeBoolean(false); // LogicPlayerCollabEventData::encode
        stream.writeBoolean(false); // LogicPlayerSpecialEventData::encode

        // LogicDataSeenStates::encode
        stream.writeVint(0);
        // Added LogicDataSeenStates::encode

        stream.writeBoolean(false); // LogicPlayerContestEventData::encode
        stream.writeBoolean(false); // LogicPlayerRecordsData::encode
        stream.writeBoolean(false); // LogicPlayerRecordsData::encode
        stream.writeBoolean(false); // LogicPlayerRecordsData::encode

        stream.writeVint(0);

        // LogicClientHome::encode

        // LogicClientAvatar::LogicClientAvatar

        stream.writeVlong(player.id);
        stream.writeVlong(player.id);
        stream.writeVlong({ high: 0, low: 0 });

        stream.writeString(player.name);
        stream.writeBoolean(true);
        stream.writeInt(-1);

        // commodity

        stream.writeVint(28); // comodity count

        let ownedBrawlersCount = Object.values(player.ownedBrawlers).map(brawler => brawler.cardID).length;
        stream.writeVint(ownedBrawlersCount + 8);
        for (const cardID of Object.values(player.ownedBrawlers).map(brawler => brawler.cardID)) {
            stream.writeDataReference({ high: 23, low: cardID })
            stream.writeVint(-1);
            stream.writeVint(1);
        }

        stream.addCommodityArrayValue(5, 8, player.coins);
        stream.addCommodityArrayValue(5, 24, player.bling);
        stream.addCommodityArrayValue(5, 11, 1000);
        stream.addCommodityArrayValue(5, 22, 0); // chroma tokens
        stream.addCommodityArrayValue(5, 23, 0); // fame
        stream.addCommodityArrayValue(5, 24, 0); // powerpoints
        stream.addCommodityArrayValue(5, 24, 300000);
        stream.addCommodityArrayValue(5, 25, 0); // daily streak

        stream.writeVint(ownedBrawlersCount);
        for (const cardID of Object.keys(player.ownedBrawlers).map(id => parseInt(id))) {
            const brawler = player.ownedBrawlers[cardID];
            stream.writeDataReference({ high: 16, low: cardID })
            stream.writeVint(-1);
            stream.writeVint(brawler.trophies);
        }

        stream.writeVint(ownedBrawlersCount);
        for (const cardID of Object.keys(player.ownedBrawlers).map(id => parseInt(id))) {
            const brawler = player.ownedBrawlers[cardID];
            stream.writeDataReference({ high: 16, low: cardID })
            stream.writeVint(-1);
            stream.writeVint(brawler.highestTrophies);
        }

        stream.writeVint(ownedBrawlersCount);
        for (const cardID of Object.keys(player.ownedBrawlers).map(id => parseInt(id))) {
            const brawler = player.ownedBrawlers[cardID];
            stream.writeDataReference({ high: 16, low: cardID })
            stream.writeVint(-1);
            stream.writeVint(0);
        }

        stream.writeVint(ownedBrawlersCount);
        for (const cardID of Object.keys(player.ownedBrawlers).map(id => parseInt(id))) {
            const brawler = player.ownedBrawlers[cardID];
            stream.writeDataReference({ high: 16, low: cardID })
            stream.writeVint(-1);
            stream.writeVint(brawler.powerpoints);
        }

        stream.writeVint(ownedBrawlersCount);
        for (const cardID of Object.keys(player.ownedBrawlers).map(id => parseInt(id))) {
            const brawler = player.ownedBrawlers[cardID];
            stream.writeDataReference({ high: 16, low: cardID })
            stream.writeVint(-1);
            stream.writeVint(brawler.powerlevel - 1);
        }

        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array
        stream.writeVint(0); // Array

        // end commodity?

        stream.writeVint(player.gems); // gems
        stream.writeVint(player.gems); // gems
        stream.writeVint(10);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(2);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeString("");
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeVint(0);
        stream.writeBoolean(false);
        //console.log("OwnHomeDataMessage stream dump:\n", hexdump(new Uint8Array(stream.payload).buffer));

        return stream.payload;
    }
}