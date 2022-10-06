import { Serializable } from './serializable';
import { FlattenedJWS } from 'jose';

export class SharedLog extends Serializable {
  log: FlattenedJWS;
  shareId: string;
  creator: string;

  constructor(log: FlattenedJWS, shareId: string, creator: string) {
    super();
    this.log = log;
    this.shareId = shareId;
    this.creator = creator;
  }

  static fromJson(data: string): SharedLog {
    let obj = super.fromJson(data);
    return SharedLog.fromObj(obj);
  }

  static fromBytes(data: Uint8Array): SharedLog {
    let obj = super.fromBytes(data);
    return SharedLog.fromObj(obj);
  }

  static fromObj(obj: object): SharedLog {
    if ('log' in obj && 'shareId' in obj && 'creator' in obj) {
      let emptyLog = new SharedLog({ payload: '', protected: '', signature: '' }, '', '');
      return Object.assign(emptyLog, obj);
    }
    throw Error(
      'JSON does not contain a valid SharedLog. Can not deserialize object. ' + JSON.stringify(obj)
    );
  }
}
