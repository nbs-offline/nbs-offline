import { createAssetManager } from "./utility/assetmanagerandroid.js";
import {
  base,
  config,
  load,
  loadAsset,
  player,
  setBase,
  version,
} from "./definitions.js";
import { installHooks } from "./mainHooks.js";
import { isAndroid } from "./platform.js";
import { Logger } from "./utility/logger.js";
import { Dumper } from "./utility/dump.js";
import { setupCustomSettings } from "./customsettings.js";
import { createStringObject, getPackageName } from "./util.js";

(async () => {
  if (isAndroid) await createAssetManager();
})();

let library = isAndroid ? "libg.so" : "laser";
setBase(Module.getBaseAddress(library));

load();
Logger.info("Running on", isAndroid ? "Android" : "iOS");
if (isAndroid)
  Logger.verbose("Package name:", getPackageName());
Logger.verbose(`${library} loaded at: ${base}`);
for (const brawlerKey in player.ownedBrawlers) {
  const brawler = player.ownedBrawlers[brawlerKey];
  for (const skin of brawler.skins) {
    player.ownedSkins.push(skin);
  }
}
installHooks();
if (version == 59 && Process.platform == "darwin" && config.customSettings)
  setupCustomSettings();
if (!isAndroid) {
  let dumper = new Dumper(true);
  dumper.dump("playerprofile", 0x41ba64);
}
