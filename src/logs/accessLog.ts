import { FlattenedJWS, JWSHeaderParameters } from 'jose';
import { Serializable } from './serializable';
import { Buffer } from '../globals';

/**
 * Represents a singed AccessLog.
 */
export class SignedAccessLog implements FlattenedJWS {
  payload: string;
  signature: string;
  header?: JWSHeaderParameters;
  protected?: string;

  constructor(flattenedJWS: FlattenedJWS) {
    this.payload = flattenedJWS.payload;
    this.signature = flattenedJWS.signature;
    this.header = flattenedJWS.header;
    this.protected = flattenedJWS.protected;
  }

  extract(): AccessLog {
    return AccessLog.fromFlattenedJWS(this);
  }
}

/**
 * Represents a raw AccessLog, which is not signed by a monitor.
 */
export class AccessLog extends Serializable {
  monitor: string;
  owner: string;
  tool: string;
  justification: string;
  timestamp: number;
  accessKind: string;
  dataType: string[];

  constructor(
    monitor: string,
    owner: string,
    tool: string,
    justification: string,
    timestamp: number,
    accessKind: string,
    dataType: string[]
  ) {
    super();
    this.monitor = monitor;
    this.owner = owner;
    this.tool = tool;
    this.justification = justification;
    this.timestamp = timestamp;
    this.accessKind = accessKind;
    this.dataType = dataType;
  }

  static fromFlattenedJWS(jws: FlattenedJWS): AccessLog {
    let obj = Buffer.from(jws.payload, 'base64').toString();
    return AccessLog.fromJson(obj);
  }

  static fromBytes(data: Uint8Array): AccessLog {
    let obj = super.fromBytes(data);
    return AccessLog.fromObj(obj);
  }

  static fromJson(data: string): AccessLog {
    let obj = super.fromJson(data);
    return AccessLog.fromObj(obj);
  }

  static fromObj(obj: object): AccessLog {
    if (
      'monitor' in obj &&
      'owner' in obj &&
      'tool' in obj &&
      'justification' in obj &&
      'timestamp' in obj &&
      'accessKind' in obj &&
      'dataType' in obj
    ) {
      let emptyLog = new AccessLog('', '', '', '', 0, '', []);
      return Object.assign(emptyLog, obj);
    }
    throw Error('JSON does not contain a valid AccessLog. Can not deserialize object.');
  }
}
