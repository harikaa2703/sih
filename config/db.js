const mongoose = require("mongoose");

let isConnected = false;

async function connectDB() {
    if (!process.env.MONGO_URI) {
        console.log("No MONGO_URI configured; running in standalone demo mode.");
        return;
    }
    if (isConnected) {
        return;
    }
    try {
        await mongoose.connect(process.env.MONGO_URI);
        isConnected = true;
        console.log("Connected to MongoDB successfully");
    } catch (error) {
        console.error("MongoDB connection failed:", error.message);
    }
}

module.exports = connectDB;