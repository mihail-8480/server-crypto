import {
  serverManagerFromEnvironment,
  NodeCrypto,
  BrowserCrypto,
  ServerManager,
} from "./lib";

const obj = { hello: "world" };

async function signTest(
  signer: ServerManager<unknown>,
  verifier: ServerManager<unknown>
) {
  const jwt = await signer.self.signJwt(obj, "1 hour");
  const decodedJwt = await verifier.self.verifyJwt<typeof obj>(jwt);
  console.log(decodedJwt);
}

async function encryptionTest(
  encryptor: ServerManager<unknown>,
  decryptor: ServerManager<unknown>
) {
  const encrypted = await encryptor.self.encryptBase64(obj);
  const decrypted = await decryptor.self.decryptBase64<typeof obj>(encrypted);
  console.log(decrypted);
}

async function main() {
  const browserCryptoManager = await serverManagerFromEnvironment(
    new BrowserCrypto(require("jose"))
  );

  const nodeCryptoManager = await serverManagerFromEnvironment(
    new NodeCrypto(require("crypto"), require("jsonwebtoken"))
  );

  await encryptionTest(browserCryptoManager, nodeCryptoManager);
  await encryptionTest(nodeCryptoManager, browserCryptoManager);

  await signTest(browserCryptoManager, nodeCryptoManager);
  await signTest(nodeCryptoManager, browserCryptoManager);
}

main().then();
