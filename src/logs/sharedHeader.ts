import { Serializable } from './serializable';
import { GeneralJWE } from 'jose';
import { Buffer } from '../globals';

export class SharedHeader extends Serializable {
  shareId: string;
  owner: string;
  receivers: string[];

  constructor(shareId: string, owner: string, receivers: string[]) {
    super();
    this.shareId = shareId;
    this.owner = owner;
    this.receivers = receivers;
  }

  static fromBytes(data: Uint8Array): SharedHeader {
    let obj = super.fromBytes(data);
    return SharedHeader.fromObj(obj);
  }

  static fromJson(data: string): SharedHeader {
    let obj = super.fromJson(data);
    return SharedHeader.fromObj(obj);
  }

  static fromObj(obj: object): SharedHeader {
    if ('shareId' in obj && 'owner' in obj && 'receivers' in obj) {
      let emptyHeader = new SharedHeader('', '', []);
      return Object.assign(emptyHeader, obj);
    }
    throw Error('JSON does not contain a valid SharedHeader. Can not deserialize object.');
  }

  /**
   * This function extracts the claimed SharedHeader from a JWE.
   * @param jwe
   */
  static fromJWE(jwe: GeneralJWE) {
    let protectedObj = JSON.parse(Buffer.from(jwe.protected!, 'base64').toString());
    let sharedHeaderJson = Buffer.from(protectedObj.sharedHeader.payload, 'base64').toString();
    return SharedHeader.fromJson(sharedHeaderJson);
  }
}
