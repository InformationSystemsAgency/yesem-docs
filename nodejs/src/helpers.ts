import { randomBytes, createCipheriv, createDecipheriv, Cipher, Decipher } from 'crypto';

// Generates a secure random 256 bit AES encryption key and returns it as a base64 string
// Store securely and pass it to the application as an environmental variable
const generateSecretKey = () => {
  const secretKey: Buffer = randomBytes(32);

  return secretKey.toString('base64');
}

export const AES256Encrypt = (text: string, secretKey: Buffer) => {
  const iv = randomBytes(16); // Generate a random initialization vector
  const cipher = createCipheriv('aes-256-cbc', secretKey, iv);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);

  // Return the IV and the encrypted data as hex strings, separated by a colon
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

export const AES256Decrypt = (text: string, secretKey: Buffer) => {
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift()!, 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = createDecipheriv('aes-256-cbc', secretKey, iv);

    return Buffer.concat([decipher.update(encryptedText), decipher.final()]).toString();
  }
  catch {
    return false;
  }
}
