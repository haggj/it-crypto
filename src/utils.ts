import { v4 as uuidv4 } from 'uuid';

class EncryptionData {
  asJson(): string {
    return JSON.stringify(this);
  }

  asBytes(): Uint8Array {
    return new TextEncoder().encode(this.asJson());
  }

  static fromJson(data: string) {
    return JSON.parse(data);
  }

  static fromBytes(data: Uint8Array) {
    return EncryptionData.fromJson(new TextDecoder().decode(data));
  }
}

export class AccessLog extends EncryptionData {
  data: string = 'hallo das ist ein test';
  more: number = 42;
  shareId: string = uuidv4();

  static fromBytes(data: Uint8Array) {
    return Object.assign(new AccessLog(), super.fromBytes(data));
  }
}

export class AccessLogMeta extends EncryptionData {
  shareId: string = '';
  owner: string = '';
  receivers: string[] = [];

  static fromData(shareId: string, owner: string, receivers: string[]): AccessLogMeta {
    let logMeta = new AccessLogMeta();
    logMeta.shareId = shareId;
    logMeta.owner = owner;
    logMeta.receivers = receivers;
    return logMeta;
  }

  static fromBytes(data: Uint8Array): AccessLogMeta {
    return Object.assign(new AccessLogMeta(), super.fromBytes(data));
  }
}
