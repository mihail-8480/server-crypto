import type ms from "ms";

export const AES_KEY_LEN = 32;
export const IV_LEN = 12;

export type Base64Encrypted = {
  key: string;
  iv: string;
  authTag: string;
  content: string;
};

export interface EncryptedContent {
  authTag: string;
  content: string;
}

export interface EncryptionContext {
  key: Buffer;
  iv: Buffer;
  header: EncryptedHeader;
}

export interface EncryptedHeader {
  key: string;
  iv: string;
}

export interface ICryptoProvider<TKey> {
  jwt: {
    verifyRS256(jwt: string, publicKey: TKey): Promise<object>;
    signRS256(
      obj: object,
      privateKey: TKey,
      expiresIn: ms.StringValue
    ): Promise<string>;
  };
  crypto: {
    parsePublicKey(base64url: string): Promise<TKey>;

    parsePrivateKey(base64url: string): Promise<TKey>;

    stringifyPublicKey(key: TKey): Promise<string>;

    jwkPublicKey(key: TKey): Promise<object>;

    stringifyPrivateKey(key: TKey): Promise<string>;

    randomBytes(amount: number): Promise<Buffer>;

    publicEncrypt(data: Buffer, publicKey: TKey): Promise<Buffer>;

    privateDecrypt(data: Buffer, privateKey: TKey): Promise<Buffer>;

    encrypt(
      buffer: Buffer,
      key: Buffer,
      iv: Buffer
    ): Promise<{ authTag: Buffer; content: Buffer }>;

    decrypt(
      buffer: Buffer,
      authTag: Buffer,
      key: Buffer,
      iv: Buffer
    ): Promise<Buffer>;
  };
}
