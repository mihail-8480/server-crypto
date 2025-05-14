import type { KeyObject } from "crypto";
import { ICryptoProvider } from "../base";
import { normalizeBase64, toBase64URL } from "../base64-utils";
import type { StringValue } from "ms";

const AES_ALGO = "aes-256-gcm";

function cryptoFrom(
  module: typeof import("crypto")
): ICryptoProvider<KeyObject>["crypto"] {
  return {
    async stringifyPrivateKey(key: KeyObject): Promise<string> {
      return toBase64URL(
        key.export({ format: "der", type: "pkcs8" }).toString("base64")
      );
    },

    async stringifyPublicKey(key: KeyObject): Promise<string> {
      return toBase64URL(
        key.export({ type: "spki", format: "der" }).toString("base64")
      );
    },

    async jwkPublicKey(key: KeyObject): Promise<object> {
      return key.export({ format: "jwk" });
    },

    async parsePrivateKey(base64url: string): Promise<KeyObject> {
      return module.createPrivateKey({
        key: Buffer.from(normalizeBase64(base64url), "base64"),
        format: "der",
        type: "pkcs8",
      });
    },
    async parsePublicKey(base64url: string): Promise<KeyObject> {
      return module.createPublicKey({
        key: Buffer.from(normalizeBase64(base64url), "base64"),
        format: "der",
        type: "spki",
      });
    },
    async randomBytes(amount: number): Promise<Buffer> {
      return module.randomBytes(amount);
    },
    async publicEncrypt(data: Buffer, publicKey: KeyObject): Promise<Buffer> {
      return module.publicEncrypt(
        {
          key: publicKey,
          padding: module.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        data
      );
    },
    async privateDecrypt(data: Buffer, privateKey: KeyObject): Promise<Buffer> {
      return module.privateDecrypt(
        {
          key: privateKey,
          padding: module.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
        data
      );
    },
    async encrypt(
      buffer: Buffer,
      key: Buffer,
      iv: Buffer
    ): Promise<{ authTag: Buffer; content: Buffer }> {
      const cipher = module.createCipheriv(AES_ALGO, key, iv);
      const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
      const authTag = cipher.getAuthTag();
      return { authTag, content: encrypted };
    },
    async decrypt(
      buffer: Buffer,
      authTag: Buffer,
      key: Buffer,
      iv: Buffer
    ): Promise<Buffer> {
      const decipher = module.createDecipheriv(AES_ALGO, key, iv);
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(buffer), decipher.final()]);
    },
  };
}

function jwtFrom(
  module: typeof import("jsonwebtoken")
): ICryptoProvider<KeyObject>["jwt"] {
  return {
    async verifyRS256(jwt: string, publicKey: KeyObject): Promise<object> {
      return module.verify(jwt, publicKey, {
        algorithms: ["RS256"],
      }) as object;
    },
    async signRS256(
      obj: object,
      privateKey: KeyObject,
      expiresIn: StringValue
    ): Promise<string> {
      return module.sign(obj, privateKey, {
        algorithm: "RS256",
        expiresIn: expiresIn,
      });
    },
  };
}

export class NodeCrypto implements ICryptoProvider<KeyObject> {
  constructor(
    crypto: typeof import("crypto"),
    jsonwebtoken: typeof import("jsonwebtoken")
  ) {
    this.crypto = cryptoFrom(crypto);
    this.jwt = jwtFrom(jsonwebtoken);
  }
  jwt: ICryptoProvider<KeyObject>["jwt"];
  crypto: ICryptoProvider<KeyObject>["crypto"];
}
