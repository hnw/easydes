`use strict`;

const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const IV_LENGTH = {
  bf: 8,
  des: 8,
  'des3': 8,
  'aes-128-cbc': 16
}
const KEY_LENGTH = {
  bf: 8,
  des: 8,
  'des3': 24,
  'aes-128-cbc': 16
}

class Easydes {
  constructor(password) {
    this._algorithm = 'des';
    let str = '';
    str += password || Easydes.getPasswordFromFile();
    
    this._password = str.substring(0, KEY_LENGTH[this._algorithm]);
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
    let iv = crypto.randomBytes(IV_LENGTH[this._algorithm]);
    let password = this._password.substring(0, KEY_LENGTH[this._algorithm]);
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
    let iv = decoded.slice(0, 8);
    let encrypted = decoded.slice(8, len - (len % 8));
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
