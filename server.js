require("dotenv").config();
const _ = require("lodash");
const fs = require("fs");
const token = process.env.TOKEN;
const serverPublicKey = fs.readFileSync("ignore/server-public-key.pem");
const io = require("socket.io-client");
/**
 * @type {io.Socket}
 */
const socket = io("http://localhost:3358", {
  auth: { token: token },
});

const { generateKeyPairSync, publicDecrypt } = require("node:crypto");
const { privateDecrypt } = require("crypto");

// Create a folder named "ignore" if it doesn't exist
const folderPath = "./ignore";
if (!fs.existsSync(folderPath)) {
  fs.mkdirSync(folderPath);
}

// Function to check if a file exists
function fileExists(filePath) {
  try {
    fs.accessSync(filePath);
    return true;
  } catch (err) {
    return false;
  }
}

// Function to load key from file or generate new key
function loadOrGenerateKey(filePath, generateFunction) {
  if (fileExists(filePath)) {
    // If the file exists, read the key from the file
    return fs.readFileSync(filePath, "utf-8");
  } else {
    // If the file doesn't exist, generate a new key
    const key = generateFunction();
    fs.writeFileSync(filePath, key, { encoding: "utf-8" });
    return key;
  }
}

// Load or generate the private key
const privateKeyFilePath = "./ignore/private-key.pem";
const privateKeyPEM = loadOrGenerateKey(privateKeyFilePath, () => {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return privateKey.export({ type: "pkcs1", format: "pem" });
});

// Load or generate the public key
const publicKeyFilePath = "./ignore/public-key.pem";
const publicKeyPEM = loadOrGenerateKey(publicKeyFilePath, () => {
  const { publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return publicKey.export({ type: "pkcs1", format: "pem" });
});
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
