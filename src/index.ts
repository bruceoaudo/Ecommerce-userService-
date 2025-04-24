import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import path from "path";
import dotenv from 'dotenv'
import { LoginUser, RegisterUser, VerifyToken } from "./auth";
import { connectDB } from "./config/db";

dotenv.config()
const PORT = process.env.PORT || "50052";

const PROTO_PATH = path.join(__dirname, "../proto/users.proto");

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const proto = grpc.loadPackageDefinition(packageDefinition) as any;

const authService = {
  RegisterUser: RegisterUser,

    LoginUser: LoginUser,
  
    VerifyToken: VerifyToken,
};


const server = new grpc.Server();

server.addService(proto.user.AuthService.service, authService);

const start = async () => {
  await connectDB();

  server.bindAsync(
    `0.0.0.0:${PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (err, port) => {
      if (err) throw err;
      console.log(`userService running on port ${port}`);
    }
  );
};

start().catch(console.error);

// Graceful shutdown handlers
process.on("SIGINT", () => {
  console.log("SIGINT received. Shutting down gracefully...");
  server.tryShutdown(() => {
    console.log("Server shutdown complete");
    process.exit(0);
  });
});

process.on("SIGTERM", () => {
  console.log("SIGTERM received. Shutting down gracefully...");
  server.tryShutdown(() => {
    console.log("Server shutdown complete");
    process.exit(0);
  });
});

// Error handlers
["uncaughtException", "unhandledRejection"].forEach((event) => {
  process.on(event, (error) => {
    console.error(`${event}:`, error);
  });
});
