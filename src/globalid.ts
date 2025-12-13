export class GlobalID {
  static createGlobalID(classID: number, instanceID: number): number {
    return classID <= 0 ? 1000000 + instanceID : classID * 1000000 + instanceID;
  }

  static getClassID(globalID: number): number {
    return Math.floor(globalID / 1000000);
  }

  static getInstanceID(globalID: number): number {
    return globalID % 1000000;
  }
}
