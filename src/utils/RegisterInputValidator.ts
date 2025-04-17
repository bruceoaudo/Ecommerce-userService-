import { User } from "../schema/user";
import validator from "validator";
import { BadRequestError } from "./bad-request-error";

interface UserInput {
  fullName: string;
  phone: string;
  email: string;
  password: string;
  confirmPassword: string;
}

export const validateRegisterUserInput = async (input: UserInput) => {
  const { fullName, phone, email, password, confirmPassword } = input;

  // 1. Trim and sanitize all inputs
  const sanitizedInput = {
    fullName: validator.trim(fullName),
    phone: validator.trim(phone),
    email: validator.normalizeEmail(validator.trim(email)) || "",
    password: validator.trim(password),
    confirmPassword: validator.trim(confirmPassword),
  };

  // 2. Validate required fields
  if (
    !sanitizedInput.fullName ||
    !sanitizedInput.phone ||
    !sanitizedInput.email ||
    !sanitizedInput.password
  ) {
    throw new BadRequestError("All fields are required");
  }

  // 3. Validate email format and prevent header injection
  if (!validator.isEmail(sanitizedInput.email)) {
    throw new BadRequestError("Invalid email format");
  }

  // 4. Validate phone number (basic international format check)
  if (
    !validator.isMobilePhone(sanitizedInput.phone, "any", { strictMode: true })
  ) {
    throw new BadRequestError("Invalid phone number");
  }

  // 5. Prevent XSS in fullName
  if (validator.contains(sanitizedInput.fullName, ["<", ">", "script"])) {
    throw new BadRequestError("Invalid characters in name");
  }

  // 6. Password strength validation (OWASP minimum requirements)
  if (!validator.isLength(sanitizedInput.password, { min: 8 })) {
    throw new BadRequestError("Password must be at least 8 characters");
  }
  if (!validator.matches(sanitizedInput.password, /[A-Z]/)) {
    throw new BadRequestError(
      "Password must contain at least one uppercase letter"
    );
  }
  if (!validator.matches(sanitizedInput.password, /[a-z]/)) {
    throw new BadRequestError(
      "Password must contain at least one lowercase letter"
    );
  }
  if (!validator.matches(sanitizedInput.password, /[0-9]/)) {
    throw new BadRequestError("Password must contain at least one number");
  }

  // 7. Password confirmation match
  if (sanitizedInput.password !== sanitizedInput.confirmPassword) {
    throw new BadRequestError("Passwords do not match");
  }

  // 8. Check for existing user (NoSQL injection protection built into Mongoose)
  const existingUser = await User.findOne({ email: sanitizedInput.email });
  if (existingUser) {
    throw new BadRequestError("Email already in use");
  }

  // Return sanitized and validated data
  return {
    fullName: sanitizedInput.fullName,
    phone: sanitizedInput.phone,
    email: sanitizedInput.email,
    password: sanitizedInput.password,
  };
};
