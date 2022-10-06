export class Serializable {
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
    return Serializable.fromJson(new TextDecoder().decode(data));
  }
}
