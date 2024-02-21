export class TextCoding {
  #encoder;
  #decoder;

  constructor() {
    this.#encoder = new TextEncoder();
    this.#decoder = new TextDecoder();
  }

  toArrayBuffer(text) {
    return this.#encoder.encode(text);
  }

  fromArrayBuffer(buffer) {
    return this.#decoder.decode(buffer);
  }
}