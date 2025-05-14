import {
  EncryptedContent,
  EncryptedHeader,
  EncryptionContext,
  ICryptoProvider,
} from "./base";

import { Server } from "./server";
import { CurrentServer } from "./current-server";
import { RemoteServer } from "./remote-server";
import { ServerManager } from "./server-manager";
import { AsyncTransform } from "@mojsoski/async-stream";
import { NodeCrypto } from "./opt/node-crypto";
import { BrowserCrypto } from "./opt/browser-crypto";

export type {
  EncryptedContent,
  EncryptedHeader,
  EncryptionContext,
  ICryptoProvider,
};

export {
  Server,
  CurrentServer,
  RemoteServer,
  ServerManager,
  NodeCrypto,
  BrowserCrypto,
};

export async function serverManagerFromEnvironment<TKey>(
  provider: ICryptoProvider<TKey>
) {
  return new ServerManager(
    await CurrentServer.fromEnvironment(provider),
    await AsyncTransform.from(RemoteServer.fromEnvironment(provider)).toArray(),
    provider
  );
}
