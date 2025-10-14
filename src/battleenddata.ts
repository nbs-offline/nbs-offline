import { Hero } from "./hero.js";
import { Long } from "./long.js";

export class BattleEndData {
    gamemode: number;
    result: number;
    rank: number;
    mapID: Long;
    heroes: Hero[];

    constructor(gamemode: number, result: number, rank: number, mapID: Long, heroes: Hero[]) {
        this.gamemode = gamemode;
        this.result = result;
        this.rank = rank;
        this.mapID = mapID;
        this.heroes = heroes;
    }
}