// lab-seal 以 AES-256-GCM 加密与解密 Lab 文件包：本机 github-run.mjs 用它加密 lab.enc、解密下载的结果；推送到公开仓库后作为 .github/lab.mjs，在 runner 上以 LAB_KEY 解开 lab.enc 并加密结果
import {execFileSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

// resultName 是加密结果在 artifact 中的文件名
export const resultName = 'lab-result.enc';

// encrypt 加密 data，输出为 12 字节 IV、16 字节认证标签与密文
export function encrypt(key, data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

// decrypt 解密 encrypt 的输出，认证失败时抛出错误
export function decrypt(key, data) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]);
}

// pack 把 source（目录时取其内容，文件时取该文件）打成 tar.gz 并加密
export function pack(key, source) {
  const full = path.resolve(source);
  const directory = fs.statSync(full).isDirectory();
  const archive = execFileSync('tar', ['-czf', '-', directory ? '.' : path.basename(full)], {cwd: directory ? full : path.dirname(full), maxBuffer: 2 ** 31});
  return encrypt(key, archive);
}

// unpack 解密 pack 的输出并解压到 target
export function unpack(key, data, target) {
  fs.mkdirSync(target, {recursive: true});
  execFileSync('tar', ['-xzf', '-'], {cwd: target, input: decrypt(key, data)});
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const key = Buffer.from(process.env.LAB_KEY ?? '', 'base64');
  const [command, source, output] = process.argv.slice(2);
  if (command === 'open') {
    unpack(key, fs.readFileSync('lab.enc'), '.');
    fs.rmSync('lab.enc');
  } else if (command === 'seal') {
    fs.mkdirSync(output, {recursive: true});
    if (fs.existsSync(source)) fs.writeFileSync(path.join(output, resultName), pack(key, source));
  } else throw new Error(`未知命令 ${command}`);
}
