import { Config, getDefaultConfig, readConfig } from "./config";
import { addDebugFile } from "./debugmenu";
import { base, load, player, setBase, showFloaterText } from "./definitions";
import { installHooks } from "./mainHooks";
import { isAndroid } from "./platform";
import { createStringObject, nop, waitForModule } from "./util";

for (const brawlerKey in player.ownedBrawlers) {
    const brawler = player.ownedBrawlers[brawlerKey];
    for (const skin of brawler.skins) {
        player.ownedSkins.push(skin);
    }
}


(async () => {
    let library = isAndroid ? "libg.so" : "laser";
    setBase(await waitForModule(library));
    setImmediate(() => {
        console.log("isAndroid", isAndroid);
        console.log(`${library} loaded at: ${base}`);
        addDebugFile();
        load();
        installHooks();
    });
})();