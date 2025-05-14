import { AsyncReadStream, AsyncTransform } from "@mojsoski/async-stream";
import {
  AES_KEY_LEN,
  IV_LEN,
  Base64Encrypted,
  EncryptedContent,
  EncryptionContext,
  EncryptedHeader,
  ICryptoProvider,
} from "./base";

export abstract class Server<TKey> {
  public abstract get name(): string;
  public abstract get publicKey(): TKey;

  protected _provider: ICryptoProvider<TKey>;

  constructor(crypto: ICryptoProvider<TKey>) {
    this._provider = crypto;
  }

  public async verifyJwt<T extends object>(jwt: string): Promise<T> {
    return (await this._provider.jwt.verifyRS256(jwt, this.publicKey)) as T;
  }

  public async createContext(): Promise<EncryptionContext> {
    const key = await this._provider.crypto.randomBytes(AES_KEY_LEN);
    const iv = await this._provider.crypto.randomBytes(IV_LEN);

    const encryptedKey = await this._provider.crypto.publicEncrypt(
      key,
      this.publicKey
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

  public static async decrypt<TKey>(
    { key, iv }: EncryptionContext,
    content: EncryptedContent,
    provider: ICryptoProvider<TKey>
  ) {
    const authTag = Buffer.from(content.authTag, "base64");
    const encrypted = Buffer.from(content.content, "base64");
    return await provider.crypto.decrypt(encrypted, authTag, key, iv);
  }

  public encryptStream(
    stream: AsyncReadStream<Buffer>
  ): AsyncReadStream<EncryptedHeader | EncryptedContent> {
    return AsyncTransform.from(
      this.createContext().then((context) =>
        AsyncTransform.from<EncryptedHeader | EncryptedContent>([
          context.header,
        ]).concat(
          stream
            .transform()
            .map((item) => Server.encrypt(context, item, this._provider))
        )
      )
    ).stream();
  }

  public static async encrypt<TKey>(
    { key, iv }: EncryptionContext,
    content: Buffer,
    provider: ICryptoProvider<TKey>
  ): Promise<EncryptedContent> {
    const { content: encrypted, authTag } = await provider.crypto.encrypt(
      content,
      key,
      iv
    );

    return {
      content: encrypted.toString("base64"),
      authTag: authTag.toString("base64"),
    };
  }

  public async encryptBase64<T>(obj: T): Promise<string> {
    const json = Buffer.from(JSON.stringify(obj), "utf-8");

    const context = await this.createContext();

    const base64Object: Base64Encrypted = {
      ...context.header,
      ...(await Server.encrypt(context, json, this._provider)),
    };

    return Buffer.from(JSON.stringify(base64Object), "utf-8").toString(
      "base64"
    );
  }
}
