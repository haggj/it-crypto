import { randomUUID } from "crypto";

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
  data: string = "hallo das ist ein test";
  more: number = 42;
  shareId: string = randomUUID();

  static fromBytes(data: Uint8Array) {
    return super.fromBytes(data) as AccessLog;
  }
}

export class AccessLogMeta extends EncryptionData {
  shareId: string;
  owner: string;
  receivers: string[];

  constructor(shareId: string, owner: string, receivers: string[]) {
    super();
    this.shareId = shareId;
    this.owner = owner;
    this.receivers = receivers;
  }

  static fromBytes(data: Uint8Array) {
    return super.fromBytes(data) as AccessLogMeta;
  }
}
