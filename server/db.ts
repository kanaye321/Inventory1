import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';

const { Pool } = pg;
import * as schema from "@shared/schema";
import dotenv from "dotenv";

// Load environment variables first
dotenv.config();

// Declare variables that will be conditionally initialized
let pool: pg.Pool | null = null;
let db: ReturnType<typeof drizzle> | null = null;
let databaseConnected = false;

// Always attempt PostgreSQL connection first if DATABASE_URL is provided
if (process.env.DATABASE_URL) {
  console.log("🔗 Attempting PostgreSQL connection...");
  console.log("🔧 Database URL:", process.env.DATABASE_URL.replace(/:[^:@]+@/, ':****@'));
  console.log("🔧 Connection details:", {
    host: process.env.DATABASE_URL?.match(/@([^:]+):/)?.[1] || 'unknown',
    port: process.env.DATABASE_URL?.match(/:(\d+)\/[^?]+/)?.[1] || 'unknown',
    database: process.env.DATABASE_URL?.split('/').pop()?.split('?')[0] || 'unknown'
  });

  try {
    pool = new Pool({ 
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes('localhost') || process.env.DATABASE_URL.includes('127.0.0.1') 
        ? false 
        : { rejectUnauthorized: false }, // Use SSL for remote connections
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
      acquireTimeoutMillis: 60000,
    });

    // Test connection synchronously during initialization
    async function testDatabaseConnection() {
      try {
        if (!pool) return false;
        const client = await pool.connect();
        await client.query('SELECT NOW()');
        client.release();
        console.log('✅ PostgreSQL connection successful');
        console.log('✅ Using PostgreSQL database - data will persist');
        databaseConnected = true;
        return true;
      } catch (err: any) {
        console.error('❌ PostgreSQL connection failed:', err.message);
        console.error('⚠️ Falling back to in-memory storage');
        console.error('💡 Check your DATABASE_URL and database server status');

        // Clean up failed connection attempt
        if (pool) {
          try {
            await pool.end();
          } catch (cleanupErr) {
            console.error('Warning: Error during connection cleanup:', cleanupErr);
          }
          pool = null;
        }
        databaseConnected = false;
        return false;
      }
    }

    // Initialize drizzle immediately with pool
    db = drizzle(pool, { schema });

    // Test connection and update status
    testDatabaseConnection().then((connected) => {
      if (!connected && pool) {
        // Connection failed, clean up
        pool.end().catch(() => {});
        pool = null;
        db = null;
      }
    });

    pool.on('error', (err) => {
      console.error('❌ PostgreSQL connection error:', err);
      console.error('⚠️ Database connection lost - operations may fail');
      databaseConnected = false;
    });

  } catch (setupError: any) {
    console.error('❌ Failed to set up PostgreSQL connection:', setupError.message);
    console.error('⚠️ Falling back to in-memory storage');
    pool = null;
    db = null;
    databaseConnected = false;
  }
} else {
  console.log("⚠️ DATABASE_URL not provided");
  console.log("⚠️ Falling back to in-memory storage");
  console.log("💡 Add DATABASE_URL environment variable for persistent storage");
  databaseConnected = false;
}

// If no database connection, fall back to in-memory storage
if (!databaseConnected) {
  console.log("📝 Using in-memory storage - data will NOT persist between restarts");
  console.log("💡 To enable persistent storage:");
  console.log("   1. Set up PostgreSQL database in Replit");
  console.log("   2. Add DATABASE_URL to environment variables");
  console.log("   3. Restart the application");
}

// Export the variables
export { pool, db, databaseConnected };
export default db;