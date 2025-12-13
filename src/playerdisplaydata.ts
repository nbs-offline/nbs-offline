import { ByteStream } from "./bytestream.js";

export class PlayerDisplayData {
  name = "Natesworks";
  thumbnail = 0;
  namecolor = 0;

  constructor(name: string, thumbnail: number, namecolor: number) {
    this.name = name;
    this.thumbnail = thumbnail;
    this.namecolor = namecolor;
  }

  encode(stream: ByteStream): ByteStream {
    stream.writeString(this.name);
    stream.writeVint(100);
    stream.writeVint(28000000 + this.thumbnail);
    stream.writeVint(43000000 + this.namecolor);
    stream.writeVint(43000000 + this.namecolor); // haspremiumpass == + player.namecolor
    return stream;
  }
}
