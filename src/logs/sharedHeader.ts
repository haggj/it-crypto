import { Serializable } from './serializable';

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
    return Object.assign(new SharedHeader('', '', []), super.fromBytes(data));
  }
}
