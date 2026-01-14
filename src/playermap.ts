import { ByteStream } from "./bytestream";
import { getMapCount, readMapFile, writeMapToFile } from "./mapmaker";

export class PlayerMap {
  id: number[] = [0, getMapCount() + 1];
  name: string;
  gmv: number;
  theme: number;
  data: number[] = [];
  accountID: number[] = [0, 1];
  mapEnvironmentData = 0;
  avatarName = "";

  constructor(name: string, gmv: number, theme: number, id: number[], data: number[]) {
    this.name = name;
    this.gmv = gmv;
    this.theme = theme;
    this.id = id;
    this.data = data
  }

  encode(stream: ByteStream): ByteStream {
    stream.writeVLong(this.id[0], this.id[1]);
    stream.writeString(this.name);
    stream.writeVInt(this.gmv);
    stream.writeDataReference(54, this.mapEnvironmentData);
    if (this.data.length > 0) stream.writeBytes(this.data, this.data.length);
    else stream.writeInt(-1);
    stream.writeVLong(this.accountID[0], this.accountID[1]);
    stream.writeString(this.avatarName);
    stream.writeVInt(1); // state
    stream.writeLong(0, 0); // update time since epoch
    stream.writeVInt(0);
    stream.writeVInt(0); // friendly signoff count
    stream.writeVInt(0); // likes
    stream.writeVInt(0); // dislikes
    stream.writeVInt(0);

    writeMapToFile(this.id, this.name, this.gmv, this.mapEnvironmentData, "", false)

    return stream;
  }
}
