const session = require("express-session");
const { MongoStore } = require("connect-mongo");

const sessionOptions = {
    secret: process.env.SESSION_SECRET || "aegis-network-assurance-session-secret-2026",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production" && process.env.COOKIE_SECURE === "true",
        sameSite: "lax",
        maxAge: 30 * 60 * 1000
    }
};

if (process.env.MONGO_URI) {
    try {
        sessionOptions.store = MongoStore.create({
            mongoUrl: process.env.MONGO_URI,
            collectionName: "sessions",
            ttl: 30 * 60
        });
    } catch (error) {
        console.warn("Could not initialize MongoStore, falling back to memory session store:", error.message);
    }
}

const sessionMiddleware = session(sessionOptions);

module.exports = sessionMiddleware;