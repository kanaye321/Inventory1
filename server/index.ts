import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { networkInterfaces } from "os";
import { runMigrations } from "./migrate";
import { storage } from "./storage";
import { DatabaseStorage, initializeDatabase } from "./database-storage";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Import database connection status
  const { databaseConnected } = await import("./db");
  
  console.log("🔄 Starting application initialization...");
  
  let usingDatabase = false;
  
  // Add a small delay to allow connection test to complete
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Import fresh database connection status after delay
  const { databaseConnected: freshConnectionStatus, db: freshDb } = await import("./db");
  
  // Prioritize PostgreSQL - attempt database operations if connection exists
  if ((freshConnectionStatus || databaseConnected) && process.env.DATABASE_URL && freshDb) {
    try {
      console.log("🔄 Running database migrations...");
      await runMigrations();
      
      // Initialize database storage
      try {
        await initializeDatabase();
        console.log("🔄 Initializing PostgreSQL storage...");

        // Create new database storage instance
        const databaseStorage = new DatabaseStorage();

        // Replace all methods on the storage object with database storage methods
        Object.getOwnPropertyNames(DatabaseStorage.prototype).forEach(name => {
          if (name !== 'constructor' && typeof databaseStorage[name] === 'function') {
            storage[name] = databaseStorage[name].bind(databaseStorage);
          }
        });

        usingDatabase = true;
        console.log("✅ PostgreSQL storage initialized successfully!");
        console.log("✅ Data will persist between restarts");
        
      } catch (error: any) {
        console.error("❌ Failed to initialize database storage:", error.message);
        console.warn("⚠️ Falling back to in-memory storage");
        usingDatabase = false;
      }
      
    } catch (migrationError: any) {
      console.error("❌ Database migrations failed:", migrationError.message);
      console.warn("⚠️ Falling back to in-memory storage");
      usingDatabase = false;
    }
  } else {
    console.log("⚠️ PostgreSQL not available - using in-memory storage");
    console.log("📝 Data will NOT persist between server restarts");
    console.log("💡 Set up PostgreSQL database for persistent storage");
    usingDatabase = false;
  }

  // Ensure default admin user exists regardless of storage type
  setTimeout(async () => {
    try {
      console.log("🔧 Checking for default admin user...");
      const adminExists = await storage.getUserByUsername("admin");
      
      if (!adminExists) {
        console.log("🔧 Creating default admin user...");
        await storage.createUser({
          username: "admin",
          password: "admin123", 
          firstName: "Admin",
          lastName: "User",
          email: "admin@example.com",
          isAdmin: true,
          department: "IT",
          permissions: {
            assets: { view: true, edit: true, add: true },
            components: { view: true, edit: true, add: true },
            accessories: { view: true, edit: true, add: true },
            consumables: { view: true, edit: true, add: true },
            licenses: { view: true, edit: true, add: true },
            users: { view: true, edit: true, add: true },
            reports: { view: true, edit: true, add: true },
            vmMonitoring: { view: true, edit: true, add: true },
            networkDiscovery: { view: true, edit: true, add: true },
            bitlockerKeys: { view: true, edit: true, add: true },
            admin: { view: true, edit: true, add: true }
          }
        });
        console.log(`✅ Default admin user created in ${usingDatabase ? 'database' : 'memory'} storage: username=admin, password=admin123`);
      } else {
        console.log(`✅ Default admin user already exists in ${usingDatabase ? 'database' : 'memory'} storage`);
      }
    } catch (initError) {
      console.error("❌ Failed to initialize default admin user:", initError);
    }
  }, 500);
})();

async function startServer() {
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Get the local machine's IP address
  function getLocalIP() {
    const interfaces = networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const net of interfaces[name] || []) {
        // Skip over non-IPv4 and internal (i.e. 127.0.0.1) addresses
        if (net.family === 'IPv4' && !net.internal) {
          return net.address;
        }
      }
    }
    return '127.0.0.1'; // fallback
  }

  // Serve the app on port 3000
  const port = 3000;
  const host = "0.0.0.0";
  const localIP = getLocalIP();

  server.listen({
    port,
    host,
  }, () => {
    log(`serving on port ${port}`);
    console.log(`\n🚀 SRPH-MIS is running at: http://0.0.0.0:${port}`);
    console.log(`💻 Access your app through Replit's webview`);
    console.log(`🌐 Network access: http://${localIP}:${port}\n`);
  });
}

startServer();