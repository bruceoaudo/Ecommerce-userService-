import * as grpc from "@grpc/grpc-js";
import { User } from "./schema/user";
import { validateRegisterUserInput } from "./utils/RegisterInputValidator";
import { hashPassword } from "./utils/password";
import { validateLoginUserInput } from "./utils/LoginInputValidator";
import jwt, { SignOptions } from "jsonwebtoken";

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
      callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: "Registration failed",
      });
    }
}
  
interface TokenPayload {
  userId: string;
  email: string;
}

const getJwtConfig = () => {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET must be at least 32 characters long");
  }

   const expiresIn = 3600 * 24;

  return {
    secret,
    expiresIn,
    algorithm: "HS256" as const,
  };
};

// Create token for authenticated user
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

// Verify and decode token
export const VerifyToken = (
  call: grpc.ServerUnaryCall<
    { token: string },
    { userId: string; email: string }
  >,
  callback: grpc.sendUnaryData<{ userId: string; email: string }>
) => {
  try {
    const { token } = call.request;
    const { secret, algorithm } = getJwtConfig();

    const decoded = jwt.verify(token, secret, {
      algorithms: [algorithm],
    }) as TokenPayload;

    callback(null, {
      userId: decoded.userId,
      email: decoded.email,
    });
  } catch (error) {
    console.error("Token verification error:", error);
    callback({
      code: grpc.status.UNAUTHENTICATED,
      message: "Invalid or expired token",
    });
  }
};


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
      console.error("Login error:", error);
      callback({
        code: grpc.status.INTERNAL,
        message: "Login failed",
      });
    }
  }