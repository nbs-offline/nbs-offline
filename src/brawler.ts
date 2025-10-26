export class Brawler {
    cardID: number;
    skins: number[];
    trophies: number;
    highestTrophies: number;
    powerlevel: number;
    powerpoints: number;
    masteryPoints: number;
    masteryClaimed: number;
    constructor(cardID: number, skins: number[], trophies: number, highestTrophies: number, powerlevel: number, powerpoints: number, masteryPoints: number, masteryClaimed: number) {
        this.cardID = cardID;
        this.skins = skins;
        this.trophies = trophies;
        this.highestTrophies = highestTrophies;
        this.powerlevel = powerlevel;
        this.powerpoints = powerpoints;
        this.masteryPoints = masteryPoints;
        this.masteryClaimed = masteryClaimed;
    }
}