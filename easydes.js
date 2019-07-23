`use strict`;

const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const CIPHER = {
  'b': 'bf-cbc',
  'd': 'des-ede3-cbc',
  'a': 'aes-256-cbc',
}
const CIPHER_ID = {
  'bf': 'b',
  'blowfish': 'b',
  'des': 'd',
  '3des': 'd',
  'des3': 'd',
  'aes': 'a',
}
const BLOCK_SIZE = {
  'bf-cbc': 8,
  'des-ede3-cbc': 8,
  'aes-256-cbc': 16,
}
const KEY_LENGTH = {
  'bf-cbc': 32,
  'des-ede3-cbc': 24,
  'aes-256-cbc': 32,
}

class Easydes {
  constructor(spec) {
    let algorithm = '';
    let password = '';
    if (typeof spec === 'string') {
      password = String(spec || Easydes.getPasswordFromFile());
      const cipherId = password[0];
      if (!CIPHER.hasOwnProperty(cipherId)) {
        throw new Error('Unexpected Secret key length. Try "$(npm bin)/easydes --keygen"');
      }
      algorithm = CIPHER[cipherId];
      password = password.substring(1, KEY_LENGTH[algorithm]+1);
    } else if (typeof spec === 'object') {
	({algorithm,password} = spec);
    }
    this._algorithm = algorithm;
    this._password = password;
  }

  static getCipherId(algorithm) {
    if (!CIPHER_ID.hasOwnProperty(algorithm)) {
      return '';
    }
    return CIPHER_ID[algorithm];
  }

  static getKeyLength(algorithm) {
    const cipherId = Easydes.getCipherId(algorithm);
    if (!cipherId) {
      return 0;
    }
    return KEY_LENGTH[CIPHER[cipherId]];
  }

  static getPasswordFromFile(path) {
    const homedir = os.homedir();
    const keyfile = homedir + '/.easydes';
    let password = '';
    if (fs.existsSync(keyfile)) {
      password = fs.readFileSync(keyfile, {encoding: "utf-8"});
    }
    return password.trim();
  }

  encrypt(obj) {
    if (typeof obj === "string") {
      return this._encryptString(obj);
    } else if (Array.isArray(obj)) {
      return obj.map(text => this._encryptString(text));
    } else if (typeof obj === "object") {
      return this._encryptObject(obj);
    } else {
      return obj;
    }
  }

  decrypt(obj) {
    if (typeof obj === "string") {
      return this._decryptString(obj);
    } else if (Array.isArray(obj)) {
      return obj.map(text => this._decryptString(text));
    } else if (typeof obj === "object") {
      return this._decryptObject(obj);
    } else {
      return obj;
    }
  }

  _encryptObject(obj) {
    const newObj = {};
    for (let k of Object.keys(obj)) {
      newObj[k] = this.encrypt(obj[k]);
    }
    return newObj;
  }

  _decryptObject(obj) {
    const newObj = {}
    for (let k of Object.keys(obj)) {
      newObj[k] = this.decrypt(obj[k]);
    }
    return newObj;
  }

  _encryptString(rawText) {
    const blockSize = BLOCK_SIZE[this._algorithm];
    const keyLength = KEY_LENGTH[this._algorithm];
    let iv = crypto.randomBytes(blockSize);
    let password = this._password.substring(0, keyLength);
    let cipher = crypto.createCipheriv(this._algorithm, password, iv);
    let encrypted = cipher.update(rawText);
    encrypted = Buffer.concat([iv, encrypted, cipher.final()]);
    return this._base64Encode(encrypted);
  }

  _decryptString(cipherText) {
    let decoded = this._base64Decode(cipherText);
    if (decoded === '') {
      return cipherText;
    }
    const len = decoded.length;
    if (len < 16) {
      return cipherText;
    }
    const blockSize = BLOCK_SIZE[this._algorithm]
    let iv = decoded.slice(0, blockSize);
    let encrypted = decoded.slice(blockSize, len - (len % blockSize));
    let decipher = crypto.createDecipheriv(this._algorithm, this._password, iv);
    let decrypted;
    try {
      decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
    } catch(error) {
      // OpenSSL error may have occurred
      return cipherText;
    }
    return decrypted.toString('utf8');
  }

  _base64Decode(encodedText) {
    if (!encodedText.endsWith('==')) {
      return '';
    }
    return Buffer.from(encodedText, 'base64');
  }

  _base64Encode(buffer) {
    let newBuffer = buffer;
    if (buffer.length % 3 == 0) {
      newBuffer = Buffer.concat([buffer, crypto.randomBytes(1)]);
    } else if (buffer.length % 3 == 2) {
      newBuffer = Buffer.concat([buffer, crypto.randomBytes(2)]);
    }
    return newBuffer.toString('base64');
  }
}

module.exports = Easydes;
