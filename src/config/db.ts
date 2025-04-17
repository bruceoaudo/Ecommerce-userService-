import mongoose from "mongoose";

export async function connectDB() {
  try {
    const conn = await mongoose.connect(
      process.env.MONGODB_URI!
    );
    console.log(`UserService DB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error("Database connection error:", error);
    process.exit(1);
  }
}
