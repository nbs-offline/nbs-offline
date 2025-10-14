import { base, load, player, setBase, showFloaterText } from "./definitions.js";
import { installHooks } from "./mainHooks.js";
import { isAndroid } from "./platform.js";
import { createStringObject, waitForModule } from "./util.js";

for (const brawlerKey in player.ownedBrawlers) {
    const brawler = player.ownedBrawlers[brawlerKey];
    for (const skin of brawler.skins) {
        player.ownedSkins.push(skin);
    }
}

(async () => {
    let library = isAndroid ? "libg.so" : "laser";
    setBase(await waitForModule(library));
    console.log("isAndroid", isAndroid);
    console.log(`${library} loaded at: ${base}`);
    setImmediate(() => {
        load();
        installHooks();
    });
})();