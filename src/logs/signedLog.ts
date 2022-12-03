import { FlattenedJWS, JWSHeaderParameters } from 'jose';
import { AccessLog } from './accessLog';

/**
 * Represents a singed log. A log must always be singed by a monitor.
 */
export class SignedLog implements FlattenedJWS {
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
