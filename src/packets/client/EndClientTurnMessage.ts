import { Player } from "../../player.js";
import { ByteStream } from "../../bytestream.js";
import { CommandHandler } from "../../commandhandler.js";

export class EndClientTurnMessage {
  static decode(stream: ByteStream) {
    stream.readBoolean();
    let tick = stream.readVint();
    let checksum = stream.readVint();
    let count = stream.readVint();
    console.log("Command amount:", count);
    return { stream, tick, checksum, count };
  }

  // idk how to do this well fuck this
  static execute(data: {
    stream: ByteStream;
    tick: number;
    checksum: number;
    count: number;
  }) {
    let { stream, count } = data;
    for (let i = 0; i < count; i++) {
      let id = stream.readVint();
      console.log("Command ID:", id);
      stream = CommandHandler.handleCommand(id, stream);
    }
  }
}
