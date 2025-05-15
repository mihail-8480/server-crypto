import { ICryptoProvider } from "../base";
import { normalizeBase64, toBase64URL } from "../base64-utils";
import type { JWTPayload } from "jose";

function bufferToBase64url(buf: ArrayBuffer): string {
  return toBase64URL(Buffer.from(buf).toString("base64"));
}

function base64urlToBuffer(base64url: string): Buffer {
  return Buffer.from(normalizeBase64(base64url), "base64");
}

function cryptoFrom(): ICryptoProvider<CryptoKey>["crypto"] {
  return {
    async stringifyPrivateKey(key: CryptoKey): Promise<string> {
      const exported = await crypto.subtle.exportKey("pkcs8", key);
      return bufferToBase64url(exported);
    },

    async stringifyPublicKey(key: CryptoKey): Promise<string> {
      const exported = await crypto.subtle.exportKey("spki", key);
      return bufferToBase64url(exported);
    },

    async jwkPublicKey(key: CryptoKey): Promise<object> {
      const verifyKey = await crypto.subtle.importKey(
        "spki",
        await crypto.subtle.exportKey("spki", key),
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
        },
        true,
        ["verify"]
      );

      return await crypto.subtle.exportKey("jwk", verifyKey);
    },

    async parsePrivateKey(base64url: string): Promise<CryptoKey> {
      const keyData = base64urlToBuffer(base64url);
      return await crypto.subtle.importKey(
        "pkcs8",
        keyData,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["decrypt"]
      );
    },

    async parsePublicKey(base64url: string): Promise<CryptoKey> {
      const keyData = base64urlToBuffer(base64url);
      return await crypto.subtle.importKey(
        "spki",
        keyData,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["encrypt"]
      );
    },

    async randomBytes(amount: number): Promise<Buffer> {
      const array = new Uint8Array(amount);
      crypto.getRandomValues(array);
      return Buffer.from(array);
    },

    async publicEncrypt(data: Buffer, publicKey: CryptoKey): Promise<Buffer> {
      const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        data
      );
      return Buffer.from(encrypted);
    },

    async privateDecrypt(data: Buffer, privateKey: CryptoKey): Promise<Buffer> {
      const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        data
      );
      return Buffer.from(decrypted);
    },

    async encrypt(
      buffer,
      keyBuf,
      iv
    ): Promise<{ authTag: Buffer; content: Buffer }> {
      const key = await crypto.subtle.importKey(
        "raw",
        keyBuf,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );

      const encrypted = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          tagLength: 128,
        },
        key,
        buffer
      );

      const data = new Uint8Array(encrypted);
      const tag = data.slice(data.length - 16);
      const content = data.slice(0, data.length - 16);

      return {
        authTag: Buffer.from(tag),
        content: Buffer.from(content),
      };
    },

    async decrypt(buffer, authTag, keyBuf, iv): Promise<Buffer> {
      const key = await crypto.subtle.importKey(
        "raw",
        keyBuf,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      const fullData = new Uint8Array([...buffer, ...authTag]);

      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          tagLength: 128,
        },
        key,
        fullData
      );

      return Buffer.from(decrypted);
    },
  };
}

function jwtFrom(
  module: typeof import("jose")
): ICryptoProvider<CryptoKey>["jwt"] {
  return {
    async signRS256(obj, privateKey, expiresIn) {
      const signKey = await crypto.subtle.importKey(
        "pkcs8",
        await crypto.subtle.exportKey("pkcs8", privateKey),
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
        },
        true,
        ["sign"]
      );

      const alg = "RS256";
      const jwt = await new module.SignJWT(obj as JWTPayload)
        .setProtectedHeader({ alg })
        .setExpirationTime(expiresIn)
        .setIssuedAt()
        .sign(signKey);
      return jwt;
    },

    async verifyRS256(jwt, publicKey) {
      const verifyKey = await crypto.subtle.importKey(
        "spki",
        await crypto.subtle.exportKey("spki", publicKey),
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
        },
        true,
        ["verify"]
      );
      const { payload } = await module.jwtVerify(jwt, verifyKey, {
        algorithms: ["RS256"],
      });
      return payload;
    },
  };
}

export class BrowserCrypto implements ICryptoProvider<CryptoKey> {
  constructor(jsonwebtoken: typeof import("jose")) {
    this.crypto = cryptoFrom();
    this.jwt = jwtFrom(jsonwebtoken);
  }

  jwt: ICryptoProvider<CryptoKey>["jwt"];
  crypto: ICryptoProvider<CryptoKey>["crypto"];
}
