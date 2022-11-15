import { Serializable } from './serializable';
import { FlattenedJWS } from 'jose';

export class SharedLog extends Serializable {
  log: FlattenedJWS;
  recipients: string[];
  creator: string;

  constructor(log: FlattenedJWS, recipients: string[], creator: string) {
    super();
    this.log = log;
    this.recipients = recipients;
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
    if ('log' in obj && 'recipients' in obj && 'creator' in obj) {
      let emptyLog = new SharedLog({ payload: '', protected: '', signature: '' }, [''], '');
      return Object.assign(emptyLog, obj);
    }
    throw Error(
      'JSON does not contain a valid SharedLog. Can not deserialize object. ' + JSON.stringify(obj)
    );
  }
}
