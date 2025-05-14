import { ICryptoProvider } from "./base";
import { CurrentServer } from "./current-server";
import { RemoteServer } from "./remote-server";
import { Server } from "./server";

export class ServerManager<TKey> {
  private _currentServer: CurrentServer<TKey>;
  private _servers: Map<string, RemoteServer<TKey>>;
  private _provider: ICryptoProvider<TKey>;
  constructor(
    currentServer: CurrentServer<TKey>,
    remotes: Iterable<RemoteServer<TKey>>,
    provider: ICryptoProvider<TKey>
  ) {
    this._provider = provider;
    this._currentServer = currentServer;
    this._servers = new Map<string, RemoteServer<TKey>>(
      [...remotes].map(
        (remote) =>
          [remote.name.toLocaleLowerCase(), remote] as [
            string,
            RemoteServer<TKey>
          ]
      )
    );
  }

  get self(): CurrentServer<TKey> {
    return this._currentServer;
  }

  async *publicKeys(): AsyncIterable<
    [
      string,
      { "application/pkix-spki": string; "application/jwk+json": object }
    ]
  > {
    yield [
      this.self.name,
      {
        "application/pkix-spki": await this._provider.crypto.stringifyPublicKey(
          this.self.publicKey
        ),
        "application/jwk+json": await this._provider.crypto.jwkPublicKey(
          this.self.publicKey
        ),
      },
    ];
    for (const [name, server] of this._servers) {
      yield [
        name,
        {
          "application/pkix-spki":
            await this._provider.crypto.stringifyPublicKey(server.publicKey),
          "application/jwk+json": await this._provider.crypto.jwkPublicKey(
            server.publicKey
          ),
        },
      ];
    }
  }

  get(name: string): Server<TKey> | undefined {
    const lowercaseName = name.toLocaleLowerCase();
    if (lowercaseName === this._currentServer.name.toLocaleLowerCase()) {
      return this._currentServer;
    }
    return this._servers.get(lowercaseName);
  }
}
