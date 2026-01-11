import crypto from "crypto";
import fs from "fs/promises";
import dotenv from "dotenv";
dotenv.config();

/**
 * Load AES-256 key from Base64 env var.
 */
function getKey() {
  const b64 = process.env.DEV_AES_KEY_B64;
  if (!b64) {
    throw new Error("DEV_AES_KEY_B64 env var not set");
  }

  const key = Buffer.from(b64, "base64");
  if (key.length !== 32) {
    throw new Error("DEV_AES_KEY_B64 must decode to 32 bytes");
  }

  return key;
}

/**
 * Encrypt UTF-8 text → base64( IV || ciphertext ).
 */
export function encryptText(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(16);

  const plainBuf = Buffer.isBuffer(plaintext)
    ? plaintext
    : Buffer.from(plaintext, "utf8");

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  cipher.setAutoPadding(true);

  const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const blob = Buffer.concat([iv, ciphertext]);

  return blob.toString("base64");
}

/**
 * Decrypt base64( IV || ciphertext ) → UTF-8 text.
 */
export function decryptText(base64Blob) {
  const key = getKey();
  const blob = Buffer.from(base64Blob, "base64");

  if (blob.length < 16) {
    throw new Error("Ciphertext blob too short");
  }

  const iv = blob.subarray(0, 16);
  const ciphertext = blob.subarray(16);

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  decipher.setAutoPadding(true);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return plaintext.toString("utf8");
}

/**
 * Encrypt a file (UTF-8 or binary).
 */
export async function encryptFile(inputPath, outputPath, asBinary = false) {
  const key = getKey();
  const iv = crypto.randomBytes(16);

  const data = await fs.readFile(inputPath);
  const plainBuf = asBinary ? data : Buffer.from(data.toString("utf8"), "utf8");

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  cipher.setAutoPadding(true);

  const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const blob = Buffer.concat([iv, ciphertext]);

  await fs.writeFile(outputPath, blob.toString("base64"), "utf8");
}

/**
 * Decrypt a file previously encrypted by encryptFile.
 */
export async function decryptFile(inputPath, outputPath, asBinary = false) {
  const key = getKey();
  const base64 = await fs.readFile(inputPath, "utf8");
  const blob = Buffer.from(base64, "base64");

  if (blob.length < 16) {
    throw new Error("Ciphertext blob too short");
  }

  const iv = blob.subarray(0, 16);
  const ciphertext = blob.subarray(16);

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  decipher.setAutoPadding(true);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  await fs.writeFile(outputPath, plaintext, asBinary ? undefined : "utf8");
}

/**
 * Generate a single 19-digit Luhn-valid dummy number.
 */
function generateLuhn19() {
  const bytes = crypto.randomBytes(9);
  let base = BigInt("0x" + bytes.toString("hex"))
    .toString()
    .padStart(18, "0")
    .slice(0, 18);

  const digits = base.split("").map(Number);
  let sum = 0;
  let alt = true;

  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }

  const checkDigit = (10 - (sum % 10)) % 10;
  return base + checkDigit.toString();
}

/**
 * Generate N Luhn-valid 19-digit numbers.
 */
export function generateLuhn19Batch(count) {
  const result = [];
  for (let i = 0; i < count; i++) {
    result.push(generateLuhn19());
  }
  return result;
}