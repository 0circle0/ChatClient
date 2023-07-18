require("dotenv").config();
const {
  randomBytes,
  publicEncrypt,
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  privateDecrypt,
  
  RsaPrivateKey,
  KeyLike,
  KeyObject,
  PublicKeyInput,
  JsonWebKeyInput,
} = require("node:crypto");
const _ = require("lodash");

/**
 * @param {String} message
 */
const encryptMessage = (message) => {
  const sessionKey = randomBytes(32);
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", sessionKey, iv);
  let encrypted = cipher.update(_.isNil(message) ? "" : message, "utf8", "hex");
  encrypted += cipher.final("hex");
  const ivHex = iv.toString("hex");
  const encryptedMessageWithIV = ivHex + encrypted;

  return { sessionKey, encryptedMessageWithIV };
};

const decryptMessage = (encryptedMessageWithIV, sessionKey) => {
  const receivedIV = Buffer.from(encryptedMessageWithIV.slice(0, 32), "hex");

  // Recipient creates decipher using session key and received IV for decryption
  let decrypted;
  try {
    const decipher = createDecipheriv("aes-256-cbc", sessionKey, receivedIV);
    decrypted = decipher.update(
      encryptedMessageWithIV.slice(32),
      "hex",
      "utf8"
    );
    decrypted += decipher.final("utf8");
  } catch (err) {
    return err;
  }
  return decrypted;
};

/**
 * @param {WithImplicitCoercion<ArrayBuffer | SharedArrayBuffer>} encryptedMessageWithIV
 * @param {RsaPrivateKey | KeyLike} privateKey
 * @param {NoedeJs.ArrayBufferView} publicEncryptedSession
 */
const decryptPublicMessage = (
  encryptedMessageWithIV,
  privateKey,
  publicEncryptedSession
) => {
  const sessionKey = privateDecrypt(privateKey, publicEncryptedSession);

  return decryptMessage(encryptedMessageWithIV, sessionKey);
};

/**
 * @param {String} message
 * @param {{publicKey: RsaPrivateKey | KeyLike | RsaPublicKey, id: String}[]} publicKeysWithID
 */
const encryptPublicMessage = (message, publicKeysWithID) => {
  const { sessionKey, encryptedMessageWithIV } = encryptMessage(message);

  /**
   * @type {{encryptedSessionKey: Buffer, id: String}[]}
   */
  const packets = [];

  publicKeysWithID.forEach((publicKeyId) => {
    const { publicKey, id } = publicKeyId;
    const encryptedSessionKey = publicEncrypt(publicKey, sessionKey);
    packets.push({ encryptedSessionKey, id, encryptedMessageWithIV });
  });

  return packets;
};

/**
 * @param {string | KeyObject | Buffer | PublicKeyInput | JsonWebKeyInput} publicKey
 * */
const isValidRSAPublicKey = (publicKey) => {
  try {
    createPublicKey(publicKey);
    return true;
  } catch (err) {
    return false;
  }
};

module.exports = {
  decryptMessage,
  encryptMessage,
  encryptPublicMessage,
  isValidRSAPublicKey,
  decryptPublicMessage,
};
