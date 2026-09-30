require("dotenv").config();

const express = require("express");
const path = require("path");
const connectDB = require("./config/db");
const cookieParser=require("cookie-parser");
const sessionMiddleware=require("./config/session");
const studentRoutes = require("./routes/studentRoutes");
const authRoutes = require("./routes/authRoutes");

const port = process.env.PORT;
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(sessionMiddleware);

app.use("/",studentRoutes);
app.use("/api/auth",authRoutes)

const startServer = async()=>{
    app.listen(port, () => {
        console.log(`The server is running on the port ${port}`);
    });

    try {
        await connectDB();
    } catch (error) {
        console.error("MongoDB connection failed; the static auditor demo remains available.", error);
    }
}
startServer();