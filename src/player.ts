// TODO remove

import { Brawler } from "./brawler.js";
import { Config } from "./config.js";
import { calculateHighestTrophies, calculateTrophies } from "./util.js";

export class Player {
  token = "pXrvhSEPBUQo70jmePrPVQmHJHUQMrpWav82U1kH";
  id = [0, 1];
  namecolor = 9;
  thumbnail = 0;
  coins = 0;
  starpoints = 0;
  trophies = 0;
  highestTrophies = 0;
  trophyRoadTier = 10000;
  xp = 0;
  tokens = 0;
  level = 1;
  gems = 0;
  region = "PL";
  tokenDoublers = 0;
  selectedBrawlers = [0, 1, 2];
  ownedPins: number[] = [];
  ownedSkins: number[] = [];
  ownedThumbnails: number[] = [0];
  soloVictories = 0;
  trioVictories = 0; // 3v3s
  duoVictories = 0;
  challengeWins = 0;
  brawlPassLevel: number[] = [];
  brawlPassFreeLevel: number[] = [];
  brawlPassActive = false;
  brawlPassPlusActive = false;
  passTokens = 0;
  favouriteBrawler = 0;
  bling = 0;
  ownedBrawlers: Record<number, Brawler> = {};
  applyConfig(cfg: Config) {
    this.coins = cfg.coins;
    this.gems = cfg.gems;
    this.level = cfg.experienceLevel;
    this.xp = cfg.experience;
    this.namecolor = cfg.namecolor;
    this.thumbnail = cfg.thumbnail;
    this.trophyRoadTier = cfg.trophyRoadTier;
    this.tokens = cfg.tokens;
    this.tokenDoublers = cfg.tokenDoublers;
    this.trioVictories = cfg.trioWins;
    this.soloVictories = cfg.soloWins;
    this.duoVictories = cfg.duoWins;
    this.challengeWins = cfg.challengeWins;
    this.selectedBrawlers = cfg.selectedBrawlers;
    this.ownedBrawlers = cfg.ownedBrawlers;
    this.trophies = calculateTrophies(cfg.ownedBrawlers);
    this.highestTrophies = calculateHighestTrophies(cfg.ownedBrawlers);
    this.favouriteBrawler = cfg.favouriteBrawler;
  }
}
