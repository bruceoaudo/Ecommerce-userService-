import * as argon2 from "argon2";
import { randomBytes } from "crypto";

// Hash a password with automatically generated salt
export const hashPassword = async (password: string): Promise<string> => {
  // Generate a cryptographically secure random salt
  const salt = randomBytes(32); // 32 bytes = 256 bits

  // Argon2 configuration
  const hashingOptions = {
    type: argon2.argon2id, // hybrid of argon2i and argon2d
    salt: salt,
    memoryCost: 65536, // 64MB memory usage
    timeCost: 3, // 3 iterations
    parallelism: 1, // 1 thread/lane
    hashLength: 32, // 32 bytes output = 256 bits
  };

  return await argon2.hash(password, hashingOptions);
};

// Verify a plain text password against the stored hash
export const verifyPassword = async (
  hashedPassword: string,
  candidatePassword: string
): Promise<boolean> => {
  return await argon2.verify(hashedPassword, candidatePassword);
};
