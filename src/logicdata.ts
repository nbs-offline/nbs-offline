import { getDataByID } from "./definitions";
import { GlobalID } from "./globalid";

export class LogicData {
  ptr: NativePointer;

  constructor(classID: number, instanceID: number) {
    this.ptr = getDataByID(GlobalID.createGlobalID(classID, instanceID));
  }
}
