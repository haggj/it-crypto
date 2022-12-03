import { FlattenedJWS } from 'jose';
import { Serializable } from './serializable';
import { Buffer } from '../globals';

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
    const obj = Buffer.from(jws.payload, 'base64').toString();
    return AccessLog.fromJson(obj);
  }

  static fromBytes(data: Uint8Array): AccessLog {
    const obj = super.fromBytes(data);
    return AccessLog.fromObj(obj);
  }

  static fromJson(data: string): AccessLog {
    const obj = super.fromJson(data);
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
      const emptyLog = new AccessLog('', '', '', '', 0, '', []);
      return Object.assign(emptyLog, obj);
    }
    throw Error('JSON does not contain a valid AccessLog. Can not deserialize object.');
  }
}
