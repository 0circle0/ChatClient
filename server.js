require("dotenv").config();
const _ = require("lodash");
const fs = require("fs");
const token = process.env.TOKEN;
const serverPublicKey = fs.readFileSync("ignore/public-key.pem");
const io = require("socket.io-client");
/**
 * @type {io.Socket}
 */
const socket = io("http://localhost:3358", {
  auth: { token: token },
});

const { generateKeyPairSync, publicDecrypt } = require("node:crypto");
const { privateDecrypt } = require("crypto");

// Generate the key pair
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// Convert keys to PEM format
const privateKeyPEM = privateKey.export({ type: "pkcs1", format: "pem" });
const publicKeyPEM = publicKey.export({ type: "pkcs1", format: "pem" });

let myToken;

socket.on("connect", () => {
  console.log("Connected to the server");
  socket.emit("requestToken", publicKeyPEM);
});

socket.on("token", ({ jwtToken, validator }) => {
  myToken = validateServerToken(jwtToken);
  if (_.isNil(myToken)) {
    socket.disconnect();
    return;
  }

  const validated = privateDecrypt(privateKeyPEM, validator, (err, decrypted) => {
    if (err) {
      console.log("Token Invalid Signature");
      return undefined;
    }
    return decrypted.toString("utf8") === myToken;
  });

  if (_.isNil(validated)) {
    socket.disconnect();
    return;
  }

  socket.on("validated", () => {
    console.log("Validated");
  });
  socket.emit("validate", {validated});
});

socket.on("disconnect", (reason) => {
  console.log("Disconnected from the server:", reason);
});

const validateServerToken = (jwtToken) => {
  try {
    const tokenBuffer = publicDecrypt(serverPublicKey, jwtToken);
    myToken = tokenBuffer.toString("utf8");
    return myToken;
  } catch (err) {
    console.log("Server Token Invalid Signature");
    return undefined;
  }
};
