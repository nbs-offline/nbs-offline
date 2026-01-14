import { getMapCount, readMapFile } from "src/mapmaker.js";
import { ByteStream } from "../../../bytestream.js";
import { PlayerMap } from "../../../playermap.js";
import { Logger } from "src/utility/logger.js";
import { zlib } from "src/utility/zlib.js";

export class PlayerMapsMessage {
  static encode(): number[] {
    let stream = new ByteStream([]);

    const count = getMapCount()
    Logger.verbose("Found", count, "maps")
    stream.writeVInt(count);

    for (let i = 0; i < count; i++) {
      // Get map byte array
      let mapObj = readMapFile(`0-${i + 1}.txt`)
      let mapByteArray = []
      let map;

      if (mapObj !== null) {
        if (mapObj.map !== "") {
          mapByteArray.push(222, 2, 0, 0) // magic numbers it changes in gmv (idk about theme; this is for gemgrab)

          const compressed = zlib.compress(mapObj.map)
          for (let i = 0; i < compressed.length; i++) {
              mapByteArray.push(compressed[i] & 0xff);
          }
        }

        Logger.verbose(mapObj.map)
        map = new PlayerMap(mapObj.name, mapObj.gmv, mapObj.theme, [0, i + 1], mapByteArray);
      } else {
        Logger.error("Some weird crash case probably occured, falling back to default")
        map = new PlayerMap("Error", 0, 0, [0, i + 1], [])
      }

      // map.avatarname ? 
      stream = map.encode(stream);
    }


    return stream.payload;
  }
}
