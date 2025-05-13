import jsonwebtoken from "jsonwebtoken";
import type ms from "ms";
import crypto from "crypto";
import { assertNonNull } from "@mojsoski/assert";
import { AsyncReadStream, AsyncTransform } from "@mojsoski/async-stream";

const AES_ALGO = "aes-256-gcm";
const AES_KEY_LEN = 32;
const IV_LEN = 12;

type Base64Encrypted = {
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

export abstract class Server {
  public abstract get name(): string;
  public abstract get publicKey(): crypto.KeyObject;

  public verifyJwt<T extends object>(jwt: string): T {
    return jsonwebtoken.verify(jwt, this.publicKey, {
      algorithms: ["RS256"],
    }) as T;
  }

  public createContext(): EncryptionContext {
    const key = crypto.randomBytes(AES_KEY_LEN);
    const iv = crypto.randomBytes(IV_LEN);

    const encryptedKey = crypto.publicEncrypt(
      {
        key: this.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      key
    );

    return {
      header: {
        key: encryptedKey.toString("base64"),
        iv: iv.toString("base64"),
      },
      key,
      iv,
    };
  }

  public static decrypt(
    { key, iv }: EncryptionContext,
    content: EncryptedContent
  ) {
    const decipher = crypto.createDecipheriv(AES_ALGO, key, iv);

    const authTag = Buffer.from(content.authTag, "base64");
    const encrypted = Buffer.from(content.content, "base64");

    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  public encryptStream(
    stream: AsyncReadStream<Buffer>
  ): AsyncReadStream<EncryptedHeader | EncryptedContent> {
    const context = this.createContext();

    return AsyncTransform.from<EncryptedHeader | EncryptedContent>([
      context.header,
    ])
      .concat(stream.transform().map((item) => Server.encrypt(context, item)))
      .stream();
  }

  public static encrypt(
    { key, iv }: EncryptionContext,
    content: Buffer
  ): EncryptedContent {
    const cipher = crypto.createCipheriv(AES_ALGO, key, iv);

    const encrypted = Buffer.concat([cipher.update(content), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      content: encrypted.toString("base64"),
      authTag: authTag.toString("base64"),
    };
  }

  public encryptBase64<T>(obj: T): string {
    const json = Buffer.from(JSON.stringify(obj), "utf-8");

    const context = this.createContext();

    const base64Object: Base64Encrypted = {
      ...context.header,
      ...Server.encrypt(context, json),
    };

    return Buffer.from(JSON.stringify(base64Object), "utf-8").toString(
      "base64"
    );
  }
}

export class RemoteServer extends Server {
  #publicKey: crypto.KeyObject;
  #name: string;

  public constructor(name: string, publicKey: crypto.KeyObject) {
    super();

    this.#publicKey = publicKey;
    this.#name = name.toLocaleLowerCase();
  }
  public get name(): string {
    return this.#name;
  }

  public get publicKey(): crypto.KeyObject {
    return this.#publicKey;
  }

  public static *fromEnvironment(): Iterable<RemoteServer> {
    for (const key in process.env) {
      const value = process.env[key];
      if (!value) {
        continue;
      }
      const lowercaseKey = key.toLocaleLowerCase();
      if (!lowercaseKey.startsWith("remote_server_")) {
        continue;
      }

      const name = lowercaseKey.slice("remote_server_".length);
      yield new RemoteServer(
        name,
        crypto.createPublicKey({
          key: Buffer.from(value, "base64url"),
          format: "der",
          type: "spki",
        })
      );
    }
  }
}

export class CurrentServer extends Server {
  #publicKey: crypto.KeyObject;
  #privateKey: crypto.KeyObject;
  #name: string;

  public static fromEnvironment() {
    assertNonNull(process.env.CURRENT_SERVER_NAME, "CURRENT_SERVER_NAME");
    assertNonNull(
      process.env.CURRENT_SERVER_PUBLIC_KEY,
      "CURRENT_SERVER_PUBLIC_KEY"
    );
    assertNonNull(
      process.env.CURRENT_SERVER_PRIVATE_KEY,
      "CURRENT_SERVER_PRIVATE_KEY"
    );

    return new CurrentServer(
      process.env.CURRENT_SERVER_NAME,
      crypto.createPublicKey({
        key: Buffer.from(process.env.CURRENT_SERVER_PUBLIC_KEY, "base64url"),
        format: "der",
        type: "spki",
      }),
      crypto.createPrivateKey({
        key: Buffer.from(process.env.CURRENT_SERVER_PRIVATE_KEY, "base64url"),
        format: "der",
        type: "pkcs8",
      })
    );
  }

  public constructor(
    name: string,
    publicKey: crypto.KeyObject,
    privateKey: crypto.KeyObject
  ) {
    super();
    this.#publicKey = publicKey;
    this.#privateKey = privateKey;
    this.#name = name.toLocaleLowerCase();
  }

  public get name(): string {
    return this.#name;
  }

  public get publicKey(): crypto.KeyObject {
    return this.#publicKey;
  }

  protected get privateKey(): crypto.KeyObject {
    return this.#privateKey;
  }

  public signJwt<T extends object>(obj: T, expiresIn: ms.StringValue): string {
    return jsonwebtoken.sign(obj, this.privateKey, {
      algorithm: "RS256",
      expiresIn: expiresIn,
    });
  }

  public decryptStream(
    stream: AsyncReadStream<EncryptedHeader | EncryptedContent>
  ): AsyncReadStream<Buffer> {
    const ref = this;
    return {
      async *read(signal) {
        let context: EncryptionContext | undefined = undefined;
        for await (const item of stream.read(signal)) {
          if ("content" in item) {
            assertNonNull(
              context,
              "Received the first message before receiving the key."
            );
            yield Server.decrypt(context, item);
          } else {
            context = ref.decryptContext(item);
          }
        }
      },
      transform() {
        return new AsyncTransform(this);
      },
    };
  }

  public decryptContext(header: EncryptedHeader): EncryptionContext {
    const iv = Buffer.from(header.iv, "base64");
    const encryptedKey = Buffer.from(header.key, "base64");
    const key = crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      encryptedKey
    );

    return { key, iv, header };
  }

  public decryptBase64<T>(payloadB64: string): T {
    const payloadJson = Buffer.from(payloadB64, "base64");
    const encrypted: Base64Encrypted = JSON.parse(
      payloadJson.toString("utf-8")
    );

    const decrypted = Server.decrypt(
      this.decryptContext({ key: encrypted.key, iv: encrypted.iv }),
      { content: encrypted.content, authTag: encrypted.authTag }
    );

    return JSON.parse(decrypted.toString("utf-8"));
  }
}

function lazy<T extends {}>(fn: () => T): T {
  let value: T | undefined = undefined;
  let initialized = false;

  const handler: ProxyHandler<T> = {
    get(_, prop, receiver) {
      if (!initialized) {
        value = fn();
        initialized = true;
      }
      return Reflect.get(value as T, prop, receiver);
    },
    set(_, prop, newValue, receiver) {
      if (!initialized) {
        value = fn();
        initialized = true;
      }
      return Reflect.set(value as T, prop, newValue, receiver);
    },
    has(_, prop) {
      if (!initialized) {
        value = fn();
        initialized = true;
      }
      return prop in (value as T);
    },
    ownKeys(_) {
      if (!initialized) {
        value = fn();
        initialized = true;
      }
      return Reflect.ownKeys(value as T);
    },
    getOwnPropertyDescriptor(_, prop) {
      if (!initialized) {
        value = fn();
        initialized = true;
      }
      return Reflect.getOwnPropertyDescriptor(value as T, prop);
    },
  };

  return new Proxy<T>({} as T, handler);
}

export class ServerManager {
  public static readonly default = lazy(
    () =>
      new ServerManager(
        CurrentServer.fromEnvironment(),
        RemoteServer.fromEnvironment()
      )
  );

  private _currentServer: CurrentServer;
  private _servers: Map<string, RemoteServer>;
  constructor(currentServer: CurrentServer, remotes: Iterable<RemoteServer>) {
    this._currentServer = currentServer;
    this._servers = new Map<string, RemoteServer>(
      [...remotes].map(
        (remote) =>
          [remote.name.toLocaleLowerCase(), remote] as [string, RemoteServer]
      )
    );
  }

  get self(): CurrentServer {
    return this._currentServer;
  }

  *publicKeys(): Iterable<
    [
      string,
      { "application/pkix-spki": string; "application/jwk+json": object }
    ]
  > {
    yield [
      this.self.name,
      {
        "application/pkix-spki": this.self.publicKey
          .export({ type: "spki", format: "der" })
          .toString("base64url"),
        "application/jwk+json": this.self.publicKey.export({ format: "jwk" }),
      },
    ];
    for (const [name, server] of this._servers) {
      yield [
        name,
        {
          "application/pkix-spki": server.publicKey
            .export({ type: "spki", format: "der" })
            .toString("base64url"),
          "application/jwk+json": server.publicKey.export({ format: "jwk" }),
        },
      ];
    }
  }

  get(name: string): Server | undefined {
    const lowercaseName = name.toLocaleLowerCase();
    if (lowercaseName === this._currentServer.name.toLocaleLowerCase()) {
      return this._currentServer;
    }
    return this._servers.get(lowercaseName);
  }
}
