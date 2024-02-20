export class Encoding {
    static enc = new TextEncoder();
    static dec = new TextDecoder();
  
    static toArrayBuffer = (text) => Encoding.enc.encode(text);
    static fromArrayBuffer = (buffer) => Encoding.dec.decode(buffer);
  }