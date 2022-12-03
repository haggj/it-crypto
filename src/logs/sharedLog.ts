import { Serializable } from './serializable';
import { FlattenedJWS } from 'jose';

/**
 * Represents a shared log. It contains a nested log (which is singed by a monitor) and information
 * about the creator and intended receivers. A json-encoded SharedLog is encrypted within a JWE token.
 */
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
    const obj = super.fromJson(data);
    return SharedLog.fromObj(obj);
  }

  static fromBytes(data: Uint8Array): SharedLog {
    const obj = super.fromBytes(data);
    return SharedLog.fromObj(obj);
  }

  static fromObj(obj: object): SharedLog {
    if ('log' in obj && 'recipients' in obj && 'creator' in obj) {
      const emptyLog = new SharedLog({ payload: '', protected: '', signature: '' }, [''], '');
      return Object.assign(emptyLog, obj);
    }
    throw Error(
      'JSON does not contain a valid SharedLog. Can not deserialize object. ' + JSON.stringify(obj)
    );
  }
}
