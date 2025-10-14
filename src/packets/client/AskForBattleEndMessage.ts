import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { Config } from "../../config.js";
import { Hero } from "../../hero.js";
import { BattleEndData } from "../../battleenddata.js";
import { Messaging } from "../../messaging.js";
import { BattleEndMessage } from "../server/BattleEndMessage.js";

export class AskForBattleEndMessage {
    static decode(player: Player, stream: ByteStream): BattleEndData {
        let gamemode = stream.readVint();
        let result = stream.readVint();
        let rank = stream.readVint();
        let mapID = stream.readDataReference();
        let heroes: Hero[] = [];
        let heroCount = stream.readVint();
        for (let i = 0; i < heroCount; i++) {
            // ugly ass code
            heroes.push(new Hero(stream.readDataReference(), stream.readDataReference(), stream.readVint(), stream.readBoolean(), stream.readString()));
        }
        
        console.log("AskBattleEndMessage:", JSON.stringify(heroes, null, 2));
        return new BattleEndData(gamemode, result, rank, mapID, heroes);
    }

    static execute(player: Player, stream: ByteStream): void {
        let data = this.decode(player, stream);
        Messaging.sendOfflineMessage(23456, BattleEndMessage.encode(player, data));
    }
}