import { User } from "../schema/user";
import validator from "validator";
import { BadRequestError } from "./bad-request-error";
import { verifyPassword } from "./password";

interface UserInput {
  email: string;
  password: string;
}

export const validateLoginUserInput = async (input: UserInput) => {
  const { email, password} = input;

  // 1. Trim and sanitize all inputs
  const sanitizedInput = {
    email: validator.normalizeEmail(validator.trim(email)) || "",
    password: validator.trim(password)
  };

  // 2. Validate required fields
  if (
    !sanitizedInput.email ||
    !sanitizedInput.password
  ) {
    throw new BadRequestError("All fields are required");
  }

  // 3. Validate email format and prevent header injection
  if (!validator.isEmail(sanitizedInput.email)) {
    throw new BadRequestError("Invalid email format");
  }

  // 4. Check for existing user (NoSQL injection protection built into Mongoose)
  const existingUser = await User.findOne({ email: sanitizedInput.email });
  if (!existingUser) {
    throw new BadRequestError("Invalid credentials");
  }
    
    // 5. Check if password is correct
    const passwordCorrect = await verifyPassword(existingUser.password, password)
    if (!passwordCorrect) {
      throw new BadRequestError("Invalid credentials");
    }

  // Return sanitized and validated data
  return {
    userId: existingUser._id as string,
    email: sanitizedInput.email
  };
};
