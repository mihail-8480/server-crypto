import ms from "ms";
import { assertNonNull } from "@mojsoski/assert";
import { AsyncReadStream, AsyncTransform } from "@mojsoski/async-stream";
import { Base64Encrypted, ICryptoProvider } from "./base";
import {
  EncryptedContent,
  EncryptedHeader,
  EncryptionContext,
  Server,
} from "./index";
export class CurrentServer<TKey> extends Server<TKey> {
  #publicKey: TKey;
  #privateKey: TKey;
  #name: string;

  public static async fromEnvironment<TKey>(provider: ICryptoProvider<TKey>) {
    assertNonNull(process.env.CURRENT_SERVER_NAME, "CURRENT_SERVER_NAME");
    assertNonNull(
      process.env.CURRENT_SERVER_PUBLIC_KEY,
      "CURRENT_SERVER_PUBLIC_KEY"
    );
    assertNonNull(
      process.env.CURRENT_SERVER_PRIVATE_KEY,
      "CURRENT_SERVER_PRIVATE_KEY"
    );

    return new CurrentServer<TKey>(
      process.env.CURRENT_SERVER_NAME,
      await provider.crypto.parsePublicKey(
        process.env.CURRENT_SERVER_PUBLIC_KEY
      ),
      await provider.crypto.parsePrivateKey(
        process.env.CURRENT_SERVER_PRIVATE_KEY
      ),
      provider
    );
  }

  public constructor(
    name: string,
    publicKey: TKey,
    privateKey: TKey,
    provider: ICryptoProvider<TKey>
  ) {
    super(provider);
    this.#publicKey = publicKey;
    this.#privateKey = privateKey;
    this.#name = name.toLocaleLowerCase();
  }

  public get name(): string {
    return this.#name;
  }

  public get publicKey(): TKey {
    return this.#publicKey;
  }

  protected get privateKey(): TKey {
    return this.#privateKey;
  }

  public signJwt<T extends object>(
    obj: T,
    expiresIn: ms.StringValue
  ): Promise<string> {
    return this._provider.jwt.signRS256(obj, this.privateKey, expiresIn);
  }

  public decryptStream(
    stream: AsyncReadStream<EncryptedHeader | EncryptedContent>
  ): AsyncReadStream<Buffer> {
    const provider = this._provider;
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
            yield await Server.decrypt(context, item, provider);
          } else {
            context = await ref.decryptContext(item);
          }
        }
      },
      transform() {
        return new AsyncTransform(this);
      },
    };
  }

  public async decryptContext(
    header: EncryptedHeader
  ): Promise<EncryptionContext> {
    const iv = Buffer.from(header.iv, "base64");
    const encryptedKey = Buffer.from(header.key, "base64");

    const key = await this._provider.crypto.privateDecrypt(
      encryptedKey,
      this.privateKey
    );

    return { key, iv, header };
  }

  public async decryptBase64<T>(payloadB64: string): Promise<T> {
    const payloadJson = Buffer.from(payloadB64, "base64");
    const encrypted: Base64Encrypted = JSON.parse(
      payloadJson.toString("utf-8")
    );

    const decrypted = await Server.decrypt(
      await this.decryptContext({ key: encrypted.key, iv: encrypted.iv }),
      { content: encrypted.content, authTag: encrypted.authTag },
      this._provider
    );

    return JSON.parse(decrypted.toString("utf-8"));
  }
}
