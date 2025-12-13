import { ByteStream } from "../bytestream";
import { player } from "../definitions";
import { Long } from "../long";
import { Messaging } from "../messaging";
import { TeamEntry } from "./teamentry";
import { TeamMember } from "./teammember";

export class TeamManager {
  static createTeam() {
    let entry = new TeamEntry(new Long(0, 1), 1, 5);
    entry.teamMembers.push(new TeamMember(true, 3));
    let stream = new ByteStream([]);
    Messaging.sendOfflineMessage(24124, entry.encode(stream).payload);
  }
}
