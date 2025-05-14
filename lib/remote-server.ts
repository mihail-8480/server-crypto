import { ICryptoProvider } from "./base";
import { Server } from "./server";

export class RemoteServer<TKey> extends Server<TKey> {
  #publicKey: TKey;
  #name: string;

  public constructor(
    name: string,
    publicKey: TKey,
    provider: ICryptoProvider<TKey>
  ) {
    super(provider);

    this.#publicKey = publicKey;
    this.#name = name.toLocaleLowerCase();
  }
  public get name(): string {
    return this.#name;
  }

  public get publicKey(): TKey {
    return this.#publicKey;
  }

  public static async *fromEnvironment<TKey>(
    provider: ICryptoProvider<TKey>
  ): AsyncIterable<RemoteServer<TKey>> {
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
        await provider.crypto.parsePublicKey(value),
        provider
      );
    }
  }
}
