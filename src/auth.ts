import * as grpc from "@grpc/grpc-js";
import { User } from "./schema/user";
import { validateRegisterUserInput } from "./utils/RegisterInputValidator";
import { hashPassword } from "./utils/password";
import { validateLoginUserInput } from "./utils/LoginInputValidator";
import jwt, { SignOptions } from "jsonwebtoken";
import { BadRequestError } from "./utils/bad-request-error";

/**
 * Handles user registration via gRPC.
 * @description Validates input, hashes the password, and creates a user record.
 * @param {grpc.ServerUnaryCall<any, any>} call - gRPC request call.
 * @param {grpc.sendUnaryData<any>} callback - gRPC response callback.
 * @throws {grpc.ServiceError} 
 *   - `INVALID_ARGUMENT` (3) if input validation fails.
 *   - `INTERNAL` (6) if an unknown error occurs.
 * @example
 * // gRPC call example
 * RegisterUser(request, (err, response) => { ... });
 */
export const RegisterUser = async (
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ) => {
    try {
        const validatedData = await validateRegisterUserInput(call.request);
        
        validatedData.password = await hashPassword(validatedData.password);
        
        await User.create(validatedData);

        callback(null, {
            success: true,
            message: "User registered successfully",
        });
    } catch (error) {
      console.error("Registration error:", error);
      // Check if it's a BadRequestError
      if (error instanceof BadRequestError) {
        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: error.message,
        });
      } else {
        // For other unexpected errors
        callback({
          code: grpc.status.INTERNAL,
          message: "Registration failed due to an unexpected error",
        });
      }
    }
}
  
interface TokenPayload {
  userId: string;
  email: string;
}


/**
 * Retrieves and validates JWT configuration from environment variables.
 * @description Ensures secure JWT setup by enforcing minimum secret strength and standardized algorithm.
 * 
 * @returns {Object} JWT configuration object with:
 *   - `secret`: Cryptographic secret key (from `JWT_SECRET` env var)
 *   - `expiresIn`: Token expiration in seconds (default: 86400 [24h])
 *   - `algorithm`: Signing algorithm (fixed to HS256 for security)
 * 
 * @throws {Error} If:
 *   - `JWT_SECRET` is missing or shorter than 32 characters
 *   - Environment variables are improperly configured
 * 
 * @example
 * // Basic usage
 * const { secret } = getJwtConfig();
 * 
 * @example
 * // Error case
 * try {
 *   getJwtConfig(); // Throws if JWT_SECRET undefined
 * } catch (err) {
 *   console.error("JWT setup failed:", err.message);
 * }
 * 
 * @security
 * - Enforces 256-bit (32 char) minimum secret length
 * - Uses HMAC-SHA256 (HS256) by default - override only for RSA/ECDSA
 * - Never exposes secret in client-side code
 */
const getJwtConfig = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters long");
  }

   const expiresIn = 3600 * 24; // 24 hours ( 3600 secs per hour * 24 hours)

  return {
    secret,
    expiresIn,
    algorithm: "HS256" as const,
  };
};

/**
 * Generates a signed JWT token for authenticated users.
 * @description Creates a secure token containing user claims, signed with a secret key.
 *              Tokens are time-limited and use a specified cryptographic algorithm.
 * 
 * @param {TokenPayload} user - User data to embed in the token payload.
 * @param {string} user.userId - Unique user identifier (e.g., database ID).
 * @param {string} user.email - User's email address (for identification).
 * 
 * @returns {string} Signed JWT token that includes:
 *   - `userId`: For authorization checks
 *   - `email`: For display purposes
 *   - Standard claims (`iat`, `exp`)
 * 
 * @throws {Error} If:
 *   - JWT secret is not configured
 *   - Invalid signing algorithm provided
 *   - Token serialization fails
 * 
 * @example
 * // Basic usage
 * const token = createToken({
 *   userId: "507f1f77bcf86cd799439011",
 *   email: "user@example.com"
 * });
 * 
 * @security
 * - Uses environment-configured secret (never hardcoded)
 * - Sets explicit expiration (prevent infinite sessions)
 * - Restricts to secure algorithms (default: HS256)
 * - Payload contains minimal identifiable information
 */
const createToken = (user: TokenPayload): string => {
  const { secret, expiresIn, algorithm } = getJwtConfig();

  const payload: TokenPayload = {
    userId: user.userId,
    email: user.email,
  };

  const options: SignOptions = {
    expiresIn,
    algorithm,
  };

  return jwt.sign(payload, secret, options);
};

/**
 * gRPC service method for token verification
 * @throws {grpc.ServiceError} With UNAUTHENTICATED code for invalid tokens
 */
export const VerifyToken = (
  call: grpc.ServerUnaryCall<
    { token: string },
    { userId: string; email: string }
  >,
  callback: grpc.sendUnaryData<{ userId: string; email: string }>
) => {
  try {
    const { token } = call.request;
    if (!token) {
      throw new BadRequestError("Token is required");
    }

    const { secret, algorithm } = getJwtConfig();
    const decoded = jwt.verify(token, secret, {
      algorithms: [algorithm],
      clockTolerance: 30, // 30-second leeway for clock skew
    }) as TokenPayload;

    // Validate payload structure
    if (!decoded.userId || !decoded.email) {
      throw new Error("Invalid token payload");
    }

    callback(null, {
      userId: decoded.userId,
      email: decoded.email,
    });
  } catch (error) {
    console.error("Token verification error:", error);

    // Proper type checking
    let statusCode = grpc.status.INVALID_ARGUMENT;
    let errorMessage = "Invalid token";

    if (error instanceof Error) {
      errorMessage = error.message;

      // Check for specific JWT errors
      if ("name" in error) {
        if (error.name === "TokenExpiredError") {
          statusCode = grpc.status.UNAUTHENTICATED;
        } else if (error.name === "JsonWebTokenError") {
          statusCode = grpc.status.UNAUTHENTICATED;
        }
      }
    }

    callback({
      code: statusCode,
      message: errorMessage,
    });
  }
};



/**
 * gRPC service method for authenticating users and issuing JWT tokens.
 * @description Validates login credentials, generates a JWT upon success, 
 *              and handles errors according to gRPC status codes.
 * 
 * @param {grpc.ServerUnaryCall<LoginUserRequest, any>} call - gRPC request object containing:
 *   - `request.email`: User's email address
 *   - `request.password`: User's plaintext password
 * @param {grpc.sendUnaryData<LoginUserResponse>} callback - gRPC response callback
 * 
 * @returns {void} Responds via callback with:
 *   - Success: { success: true, token: JWT, email: string }
 *   - Error: gRPC status code + error message
 * 
 * @throws {BadRequestError} When input validation fails (email/password format)
 * @throws {Error} For unexpected server errors
 * 
 * @example
 * // gRPC Success Response
 * {
 *   success: true,
 *   message: "Login successful",
 *   token: "eyJhbGciOiJIUzI1Ni...",
 *   email: "user@example.com"
 * }
 * 
 * @example
 * // gRPC Error Responses
 * // 1. Invalid input (INVALID_ARGUMENT)
 * { code: 3, message: "Invalid email format" }
 * 
 * // 2. Server error (INTERNAL)
 * { code: 13, message: "Login failed due to an unexpected error" }
 * 
 * @security
 * - Validates credentials against stored hashed passwords
 * - Uses HTTP-only cookies when token is consumed via HTTP gateway
 * - JWT should be signed with strong secret (HS256/RS256)
 */
export const LoginUser = async (
    call: grpc.ServerUnaryCall<any, any>,
    callback: grpc.sendUnaryData<any>
  ) => {
    try {
        const data = await validateLoginUserInput(call.request)
        const token = createToken(data)
        
      callback(null, {
        success: true,
        message: "Login successful",
        token: token,
        email: data.email,
      });
    } catch (error) {
      // Check if it's a BadRequestError
      if (error instanceof BadRequestError) {
        callback({
          code: grpc.status.INVALID_ARGUMENT,
          message: error.message,
        });
      } else {
        // For other unexpected errors
        callback({
          code: grpc.status.INTERNAL,
          message: "Login failed due to an unexpected error",
        });
      }
    }
  }