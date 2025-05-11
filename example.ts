import { ServerManager } from "./lib";

const self = ServerManager.default.self;

const obj = { hello: "world" };
console.log(self.decryptBase64<typeof obj>(self.encryptBase64(obj)));
