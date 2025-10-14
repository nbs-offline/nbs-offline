import { Long } from "./long.js";

export class Hero {
    id: Long;
    skinID: Long;
    team: number;
    isPlayer: boolean;
    name: string;

    constructor(id: Long, skinID: Long, team: number, isPlayer: boolean, name: string) {
        this.id = id;
        this.skinID = skinID;
        this.team = team;
        this.isPlayer = isPlayer;
        this.name = name;
    }
};