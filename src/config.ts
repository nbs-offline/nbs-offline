import { Brawler } from "./brawler";
import { configPath, libc } from "./definitions";
import { deleteFile, readFile, writeFile, fileExists } from "./fs";

export class Config {
    static offline: boolean = true;
    static offlineBattles: boolean = true;
    static dumpPackets: boolean = false;
    static dumpStructure: boolean = false;
    name = "Natesworks";
    coins = 0;
    gems = 0;
    starpoints = 0;
    experienceLevel = 0;
    experience = 0;
    namecolor = 0;
    thumbnail = 0;
    trophyRoadTier = 0;
    tokens = 0;
    tokenDoublers = 0;
    trioWins = 0;
    soloWins = 0;
    duoWins = 0;
    challengeWins = 0;
    selectedBrawlers = [0, 1, 2];
    enableShop = false;
    enableBrawlPass = false;
    lobbyinfo = "";
    enableClubs = false;
    brawlPassPremium = true;
    ownedBrawlers: Record<number, Brawler> = {};
    disableBots = false;
    infiniteAmmo = false;
    infiniteSuper = false;
    china = false;
    artTest = false;
    customLoadingScreen = true;
    debugMenu = true;
}

export function getDefaultConfig(): Config {
    return Java.performNow(() => {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const context = ActivityThread.currentApplication().getApplicationContext();
        const assetManager = context.getAssets();
        const InputStreamReader = Java.use("java.io.InputStreamReader");
        const BufferedReader = Java.use("java.io.BufferedReader");
        const StringBuilder = Java.use("java.lang.StringBuilder");
        const inputStream = assetManager.open("nbs/config.json");
        const isr = InputStreamReader.$new(inputStream, "UTF-8");
        const reader = BufferedReader.$new(isr);
        const sb = StringBuilder.$new();
        let line = reader.readLine();
        while (line != null) {
            sb.append(line);
            sb.append("\n");
            line = reader.readLine();
        }
        reader.close();
        inputStream.close();
        const jsonStr = sb.toString();
        const json = JSON.parse(jsonStr);
        const config: any = {};
        config.name = json.name;
        config.coins = json.coins;
        config.gems = json.gems;
        config.starpoints = json.starpoints;
        config.level = json.level;
        config.experience = json.experience;
        config.namecolor = json.namecolor;
        config.thumbnail = json.thumbnail;
        config.trophyRoadTier = json.trophyRoadTier;
        config.selectedBrawlers = json.selectedBrawlers;
        config.tokens = json.tokens;
        config.tokenDoublers = json.tokenDoublers;
        config["3v3Victories"] = json.trioWins;
        config.soloVictories = json.soloWins;
        config.duoVictories = json.duoWins;
        config.mostChallengeWins = json.challengeWins;
        config.lobbyinfo = json.lobbyinfo;
        config.enableBrawlPass = json.enableBrawlPass;
        config.enableShop = json.enableShop;
        config.enableClubs = json.enableClubs;
        config.brawlPassPremium = json.brawlPassPremium;
        config.disableBots = json.disableBots;
        config.infiniteAmmo = json.infiniteAmmo;
        config.infiniteSuper = json.infiniteSuper;
        config.china = json.china;
        config.artTest = json.artTest;
        config.customLoadingScreen = json.customLoadingScreen;
        config.debugMenu = json.debugMenu;
        config.unlockedBrawlers = {};
        for (const [id, brawler] of Object.entries(json.unlockedBrawlers as Record<string, any>)) {
            config.unlockedBrawlers[Number(id)] = {
                cardID: brawler.cardID,
                skins: brawler.skins,
                trophies: brawler.trophies,
                highestTrophies: brawler.highestTrophies,
                powerlevel: brawler.powerlevel,
                powerpoints: brawler.powerpoints
            };
        }
        return config;
    }) as unknown as Config;
}

export function tryLoadDefaultConfig() {
    let exists = fileExists(configPath);
    if (exists) {
        console.log("Configuration file exists");
        return
    }
    const defaultConfig = getDefaultConfig();
    writeFile(configPath, JSON.stringify(defaultConfig, null, 2));
    console.log("Wrote configuration file");
}

export function readConfig() {
    tryLoadDefaultConfig();
    const json = JSON.parse(readFile(configPath));
    const config = new Config();

    config.coins = json.coins;
    config.gems = json.gems;
    config.starpoints = json.starpoints;
    config.experienceLevel = json.level;
    config.experience = json.experience;
    config.namecolor = json.namecolor;
    config.thumbnail = json.thumbnail;
    config.trophyRoadTier = json["trophyRoadTier"];
    config.selectedBrawlers = json.selectedBrawlers;
    config.tokens = json.tokens;
    config.tokenDoublers = json.tokenDoublers;
    config.trioWins = json["3v3Victories"];
    config.soloWins = json.soloVictories;
    config.duoWins = json.duoVictories;
    config.challengeWins = json.mostChallengeWins;
    config.lobbyinfo = json.lobbyinfo;
    config.enableBrawlPass = json.enableBrawlPass == null ? false : json.enableBrawlPass;
    config.enableShop = json.enableShop == null ? false : json.enableShop;
    config.enableClubs = json.enableClubs == null ? false : json.enableClubs;
    config.brawlPassPremium = json.brawlPassPremium == null ? true : json.brawlPassPremium;
    config.disableBots = json.disableBots == null ? false : json.disableBots;
    config.infiniteAmmo = json.infiniteAmmo == null ? false : json.infiniteAmmo;
    config.infiniteSuper = json.infiniteSuper == null ? false : json.infiniteSuper;
    config.china = json.china == null ? false : json.china;
    config.name = json.name == null ? "Natesworks" : json.name;
    config.artTest = json.artTest == null ? false : json.artTest;
    config.customLoadingScreen = json.customLoadingScreen == null ? true : json.customLoadingScreen;
    config.debugMenu = json.debugMenu == null ? true : json.debugMenu;
    for (const [id, brawler] of Object.entries(json.unlockedBrawlers as Record<string, any>)) {
        config.ownedBrawlers[Number(id)] = new Brawler(
            brawler.cardID,
            brawler.skins,
            brawler.trophies,
            brawler.highestTrophies,
            brawler.powerlevel,
            brawler.powerpoints
        );
    }

    return config;
}

export function writeConfig(config: Config) {
    const data: any = {};

    data.name = config.name;
    data.coins = config.coins;
    data.gems = config.gems;
    data.starpoints = config.starpoints;
    data.level = config.experienceLevel;
    data.experience = config.experience;
    data.namecolor = config.namecolor;
    data.thumbnail = config.thumbnail;
    data.trophyRoadTier = config.trophyRoadTier;
    data.selectedBrawlers = config.selectedBrawlers;
    data.tokens = config.tokens;
    data.tokenDoublers = config.tokenDoublers;
    data["3v3Victories"] = config.trioWins;
    data.soloVictories = config.soloWins;
    data.duoVictories = config.duoWins;
    data.mostChallengeWins = config.challengeWins;
    data.lobbyinfo = config.lobbyinfo;
    data.enableBrawlPass = config.enableBrawlPass;
    data.enableShop = config.enableShop;
    data.enableClubs = config.enableClubs;
    data.brawlPassPremium = config.brawlPassPremium;
    data.disableBots = config.disableBots;
    data.infiniteAmmo = config.infiniteAmmo;
    data.infiniteSuper = config.infiniteSuper;
    data.china = config.china;
    data.artTest = config.artTest;
    data.customLoadingScreen = config.customLoadingScreen;
    data.debugMenu = config.debugMenu;

    data.unlockedBrawlers = {};
    for (const [id, brawler] of Object.entries(config.ownedBrawlers)) {
        data.unlockedBrawlers[Number(id)] = {
            cardID: brawler.cardID,
            skins: brawler.skins,
            trophies: brawler.trophies,
            highestTrophies: brawler.highestTrophies,
            powerlevel: brawler.powerlevel,
            powerpoints: brawler.powerpoints
        };
    }

    deleteFile(configPath);
    writeFile(configPath, JSON.stringify(data, null, 2));
}