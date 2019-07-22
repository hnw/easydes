#!/usr/bin/env node

const yargs = require('yargs')
      .alias('e', 'encrypt')
      .alias('d', 'decrypt')
      .locale('en');
const argv = yargs.argv;

const crypto = require('crypto');
const readline=require("readline");
const Easydes=require("../easydes");

const rl=readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "",
  terminal: false
});

let password = argv.password || Easydes.getPasswordFromFile();

const mainLoop = (password) => {
  easydes = new Easydes(password);
  rl.on("line", (str) => {
    if (argv.decrypt) {
      console.log(easydes.decrypt(str));
    } else {
      console.log(easydes.encrypt(str));
    }
  });
};

const getPasswordThenLoop = () => {
  process.stdin.setRawMode(true);
  rl.question('Password: ', (str) => {
    if (str !== '') {
      process.stdin.setRawMode(false);
      console.log();
      mainLoop(str);
    } else {
      console.log();
      getPasswordThenLoop();
    }
  });
};

const generateKey = () => {
  const pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#^+_-=:/.,~]}'
  let randomBytes = crypto.randomBytes(12);
  let key = '';
  for (let i = 0; i < 12; i++) {
    key += pool[randomBytes[i] % pool.length];
  }
  console.log(key);
}

if (argv.keygen) {
  generateKey();
  process.exit(0);
} else if (password === '') {
  if (process.stdin.isTTY) {
    getPasswordThenLoop();
  } else {
    throw new Error('You should specify password if you use pipe');
  }
} else {
  mainLoop(password);
}
