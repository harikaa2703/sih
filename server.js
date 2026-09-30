require("dotenv").config();

const express = require("express");
const path = require("path");
const connectDB = require("./config/db");
const cookieParser = require("cookie-parser");
const sessionMiddleware = require("./config/session");
const studentRoutes = require("./routes/studentRoutes");
const authRoutes = require("./routes/authRoutes");

const port = process.env.PORT || 3000;
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(sessionMiddleware);

// API routes
app.use("/", studentRoutes);
app.use("/api/auth", authRoutes);

// SPA fallback: serves index.html for any client route or direct page reload
app.use((req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

const startServer = async () => {
    app.listen(port, () => {
        console.log(`The server is running on the port ${port}`);
    });

    try {
        await connectDB();
    } catch (error) {
        console.error("MongoDB connection failed; the static auditor demo remains available.", error);
    }
};

// Only listen directly when not running in serverless (e.g. Vercel)
if (require.main === module) {
    startServer();
}

module.exports = app;