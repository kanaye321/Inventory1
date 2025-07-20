import { db } from "./db";
import { sql } from "drizzle-orm";

export async function runMigrations() {
  try {
    console.log("🔄 Running database migrations...");

    // Test database connection first
    try {
      const result = await db.execute(sql`SELECT 1 as test`);
      console.log("✅ Database connection successful - test query result:", result);

      // Check if we can see existing tables
      const existingTables = await db.execute(sql`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public'
      `);
      console.log("📋 Existing tables in database:", existingTables.rows?.map(t => t.table_name) || []);

    } catch (connectionError) {
      console.warn("⚠️ Database connection failed, skipping migrations:", connectionError.message);
      return;
    }

    // Create extensions if needed
    await db.execute(sql`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);

    // Create users table with all necessary columns
    console.log("🔧 Creating users table...");
    const usersResult = await db.execute(sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL,
        department TEXT,
        is_admin BOOLEAN DEFAULT FALSE,
        role_id INTEGER,
        permissions JSON DEFAULT '{"assets":{"view":true,"edit":false,"add":false},"components":{"view":true,"edit":false,"add":false},"accessories":{"view":true,"edit":false,"add":false},"consumables":{"view":true,"edit":false,"add":false},"licenses":{"view":false,"edit":false,"add":false},"users":{"view":false,"edit":false,"add":false},"reports":{"view":true,"edit":false,"add":false},"vmMonitoring":{"view":true,"edit":false,"add":false},"networkDiscovery":{"view":true,"edit":false,"add":false},"bitlockerKeys":{"view":false,"edit":false,"add":false},"admin":{"view":false,"edit":false,"add":false}}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("✅ Users table created - result:", usersResult);

    // Create assets table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS assets (
        id SERIAL PRIMARY KEY,
        asset_tag TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'available',
        condition TEXT NOT NULL DEFAULT 'Good',
        purchase_date TEXT,
        purchase_cost TEXT,
        location TEXT,
        serial_number TEXT,
        model TEXT,
        manufacturer TEXT,
        notes TEXT,
        knox_id TEXT,
        ip_address TEXT,
        mac_address TEXT,
        os_type TEXT,
        assigned_to INTEGER REFERENCES users(id),
        checkout_date TEXT,
        expected_checkin_date TEXT,
        finance_updated BOOLEAN DEFAULT FALSE,
        department TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create components table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS components (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
	type TEXT NOT NULL,
        category TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 0,
        description TEXT,
        location TEXT,
        serial_number TEXT,
        model TEXT,
        manufacturer TEXT,
        purchase_date TEXT,
        purchase_cost TEXT,
        date_released TEXT,
        date_returned TEXT,
        released_by TEXT,
        returned_to TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create accessories table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS accessories (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        status TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        description TEXT,
        location TEXT,
        serial_number TEXT,
        model TEXT,
        manufacturer TEXT,
        purchase_date TEXT,
        purchase_cost TEXT,
        assigned_to INTEGER REFERENCES users(id),
        knox_id TEXT,
        date_released TEXT,
        date_returned TEXT,
        released_by TEXT,
        returned_to TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create consumables table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS consumables (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        quantity INTEGER DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'available',
        location TEXT,
        model_number TEXT,
        manufacturer TEXT,
        purchase_date TEXT,
        purchase_cost TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create licenses table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS licenses (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        key TEXT NOT NULL,
        seats TEXT,
        assigned_seats INTEGER DEFAULT 0,
        company TEXT,
        manufacturer TEXT,
        purchase_date TEXT,
        expiration_date TEXT,
        purchase_cost TEXT,
        status TEXT NOT NULL,
        notes TEXT,
        assigned_to INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create license_assignments table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS license_assignments (
        id SERIAL PRIMARY KEY,
        license_id INTEGER REFERENCES licenses(id) NOT NULL,
        assigned_to TEXT NOT NULL,
        notes TEXT,
        assigned_date TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create consumable_assignments table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS consumable_assignments (
        id SERIAL PRIMARY KEY,
        consumable_id INTEGER REFERENCES consumables(id) NOT NULL,
        assigned_to TEXT NOT NULL,
        serial_number TEXT,
        knox_id TEXT,
        quantity INTEGER NOT NULL DEFAULT 1,
        assigned_date TEXT NOT NULL,
        returned_date TEXT,
        status TEXT NOT NULL DEFAULT 'assigned',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create activities table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS activities (
        id SERIAL PRIMARY KEY,
        action TEXT NOT NULL,
        item_type TEXT NOT NULL,
        item_id INTEGER NOT NULL,
        user_id INTEGER REFERENCES users(id),
        timestamp TEXT NOT NULL,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create vm_inventory table with all required fields
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS vm_inventory (
        id SERIAL PRIMARY KEY,
        -- Date fields
        start_date TEXT,
        end_date TEXT,
        -- Host Information
        hypervisor TEXT NOT NULL,
        host_name TEXT,
        host_model TEXT,
        host_ip TEXT,
        host_os TEXT,
        rack TEXT,
        -- VM Identification
        vm_id TEXT,
        vm_name TEXT NOT NULL,
        vm_status TEXT NOT NULL DEFAULT 'stopped',
        vm_ip TEXT,
        -- Internet Access
        internet_access BOOLEAN DEFAULT FALSE,
        -- VM Operating System
        vm_os TEXT,
        vm_os_version TEXT,
        -- Usage and Tracking
        deployed_by TEXT,
        "user" TEXT,
        department TEXT,
        jira_ticket TEXT,
        -- Additional fields
        remarks TEXT,
        date_deleted TEXT,
        -- Legacy fields for compatibility
        guest_os TEXT,
        power_state TEXT,
        cpu_count INTEGER,
        memory_mb INTEGER,
        disk_gb INTEGER,
        ip_address TEXT,
        mac_address TEXT,
        vmware_tools TEXT,
        cluster TEXT,
        datastore TEXT,
        status TEXT DEFAULT 'available',
        assigned_to INTEGER REFERENCES users(id),
        location TEXT,
        serial_number TEXT,
        model TEXT,
        manufacturer TEXT,
        purchase_date TEXT,
        purchase_cost TEXT,
        created_date TEXT,
        last_modified TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create vms table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS vms (
        id SERIAL PRIMARY KEY,
        vm_name TEXT NOT NULL,
        host_name TEXT NOT NULL,
        guest_os TEXT NOT NULL,
        power_state TEXT NOT NULL DEFAULT 'stopped',
        cpu_count INTEGER DEFAULT 1,
        memory_mb INTEGER DEFAULT 1024,
        disk_gb INTEGER DEFAULT 20,
        ip_address TEXT,
        mac_address TEXT,
        vmware_tools TEXT,
        cluster TEXT,
        datastore TEXT,
        status TEXT NOT NULL DEFAULT 'available',
        assigned_to INTEGER REFERENCES users(id),
        location TEXT,
        serial_number TEXT,
        model TEXT,
        manufacturer TEXT,
        purchase_date TEXT,
        purchase_cost TEXT,
        department TEXT,
        description TEXT,
        created_date TEXT,
        last_modified TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create it_equipment table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS it_equipment (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        total_quantity INTEGER,
        assigned_quantity INTEGER DEFAULT 0,
        model TEXT,
        location TEXT,
        date_acquired TEXT,
        knox_id TEXT,
        serial_number TEXT,
        date_release TEXT,
        remarks TEXT,
        status TEXT DEFAULT 'available',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create it_equipment_assignments table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS it_equipment_assignments (
        id SERIAL PRIMARY KEY,
        equipment_id INTEGER REFERENCES it_equipment(id) NOT NULL,
        assigned_to TEXT NOT NULL,
        knox_id TEXT,
        serial_number TEXT,
        quantity INTEGER NOT NULL DEFAULT 1,
        assigned_date TEXT NOT NULL,
        returned_date TEXT,
        status TEXT NOT NULL DEFAULT 'assigned',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create system_settings table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        site_name TEXT NOT NULL DEFAULT 'SRPH-MIS',
        site_url TEXT NOT NULL DEFAULT '',
        default_language TEXT NOT NULL DEFAULT 'en',
        default_timezone TEXT NOT NULL DEFAULT 'UTC',
        allow_public_registration BOOLEAN DEFAULT FALSE,
        company_name TEXT NOT NULL DEFAULT 'SRPH',
        company_address TEXT DEFAULT '',
        company_phone TEXT DEFAULT '',
        company_email TEXT DEFAULT '',
        company_logo TEXT DEFAULT '',
        mail_driver TEXT DEFAULT '',
        mail_host TEXT DEFAULT '',
        mail_port TEXT DEFAULT '',
        mail_username TEXT DEFAULT '',
        mail_password TEXT DEFAULT '',
        mail_from_address TEXT DEFAULT '',
        mail_from_name TEXT DEFAULT '',
        asset_tag_prefix TEXT DEFAULT 'SRPH',
        asset_tag_zeros INTEGER DEFAULT 5,
        asset_auto_increment BOOLEAN DEFAULT TRUE,
        asset_checkout_policy TEXT DEFAULT '',
        asset_checkout_duration INTEGER DEFAULT 30,
        enable_login_attempts BOOLEAN DEFAULT TRUE,
        max_login_attempts INTEGER DEFAULT 5,
        lockout_duration INTEGER DEFAULT 30,
        password_min_length INTEGER DEFAULT 8,
        require_special_char BOOLEAN DEFAULT TRUE,
        require_uppercase BOOLEAN DEFAULT TRUE,
        require_number BOOLEAN DEFAULT TRUE,
        password_expiry_days INTEGER DEFAULT 90,
        enable_admin_notifications BOOLEAN DEFAULT TRUE,
        enable_user_notifications BOOLEAN DEFAULT TRUE,
        notify_on_checkout BOOLEAN DEFAULT TRUE,
        notify_on_checkin BOOLEAN DEFAULT TRUE,
        notify_on_overdue BOOLEAN DEFAULT TRUE,
        automatic_backups BOOLEAN DEFAULT FALSE,
        backup_frequency TEXT DEFAULT 'daily',
        backup_time TEXT DEFAULT '00:00',
        backup_retention INTEGER DEFAULT 30,
        maintenance_mode BOOLEAN DEFAULT FALSE,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create zabbix_settings table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS zabbix_settings (
        id SERIAL PRIMARY KEY,
        server_url TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        password TEXT NOT NULL DEFAULT '',
        api_token TEXT DEFAULT '',
        last_sync TIMESTAMP,
        sync_interval INTEGER DEFAULT 30,
        enabled BOOLEAN DEFAULT FALSE,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create zabbix_subnets table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS zabbix_subnets (
        id SERIAL PRIMARY KEY,
        cidr_range TEXT NOT NULL,
        description TEXT,
        enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create discovered_hosts table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS discovered_hosts (
        id SERIAL PRIMARY KEY,
        hostname TEXT,
        ip_address TEXT NOT NULL,
        mac_address TEXT,
        status TEXT NOT NULL DEFAULT 'new',
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source TEXT NOT NULL DEFAULT 'zabbix',
        system_info JSON DEFAULT '{}',
        hardware_details JSON DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create vm_monitoring table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS vm_monitoring (
        id SERIAL PRIMARY KEY,
        vm_id INTEGER REFERENCES assets(id),
        zabbix_id TEXT,
        status TEXT DEFAULT 'unknown',
        uptime TEXT,
        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        monitoring_enabled BOOLEAN DEFAULT TRUE,
        alerts_enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create bitlocker_keys table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS bitlocker_keys (
        id SERIAL PRIMARY KEY,
        serial_number TEXT NOT NULL,
        identifier TEXT NOT NULL,
        recovery_key TEXT NOT NULL,
        asset_id INTEGER REFERENCES assets(id),
        notes TEXT,
        date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Update existing vm_inventory table with missing columns
    console.log("🔧 Updating vm_inventory table schema...");
    const vmInventoryColumns = [
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS start_date TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS end_date TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS hypervisor TEXT NOT NULL DEFAULT \'Unknown\'',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS host_model TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS host_ip TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS host_os TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS rack TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS vm_id TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS vm_status TEXT NOT NULL DEFAULT \'stopped\'',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS vm_ip TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS internet_access BOOLEAN DEFAULT FALSE',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS vm_os TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS vm_os_version TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS deployed_by TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS "user" TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS department TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS jira_ticket TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS remarks TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS date_deleted TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS status TEXT DEFAULT \'available\'',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS assigned_to INTEGER REFERENCES users(id)',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS location TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS serial_number TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS model TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS manufacturer TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS purchase_date TEXT',
      'ALTER TABLE vm_inventory ADD COLUMN IF NOT EXISTS purchase_cost TEXT'
    ];

    for (const columnSql of vmInventoryColumns) {
      try {
        await db.execute(sql.raw(columnSql));
      } catch (error) {
        // Ignore errors for columns that already exist
        if (!error.message.includes('already exists')) {
          console.warn('Warning adding column:', error.message);
        }
      }
    }

    // Create settings table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS settings (
        id SERIAL PRIMARY KEY,
        site_name TEXT DEFAULT 'SRPH-MIS',
        site_url TEXT DEFAULT 'https://localhost:3000',
        theme TEXT DEFAULT 'light',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert default settings if not exists
    await db.execute(sql`
      INSERT INTO settings (site_name, site_url, theme)
      SELECT 'SRPH-MIS', 'https://localhost:3000', 'light'
      WHERE NOT EXISTS (SELECT 1 FROM settings)
    `);

    // Insert default system settings if not exists
    await db.execute(sql`
      INSERT INTO system_settings (site_name, company_name)
      SELECT 'SRPH-MIS', 'SRPH'
      WHERE NOT EXISTS (SELECT 1 FROM system_settings)
    `);

    // Create default admin user if it doesn't exist
    const adminCheck = await db.execute(sql`
      SELECT COUNT(*) as count FROM users WHERE username = 'admin'
    `);

    if (adminCheck.rows?.[0]?.count === 0) {
      console.log("🔧 Creating default admin user...");
      await db.execute(sql`
        INSERT INTO users (username, password, first_name, last_name, email, department, is_admin, permissions)
        VALUES (
          'admin', 
          'admin123', 
          'Admin', 
          'User', 
          'admin@example.com', 
          'IT', 
          true,
          '{"assets":{"view":true,"edit":true,"add":true},"components":{"view":true,"edit":true,"add":true},"accessories":{"view":true,"edit":true,"add":true},"consumables":{"view":true,"edit":true,"add":true},"licenses":{"view":true,"edit":true,"add":true},"users":{"view":true,"edit":true,"add":true},"reports":{"view":true,"edit":true,"add":true},"vmMonitoring":{"view":true,"edit":true,"add":true},"networkDiscovery":{"view":true,"edit":true,"add":true},"bitlockerKeys":{"view":true,"edit":true,"add":true},"admin":{"view":true,"edit":true,"add":true}}'
        )
      `);
      console.log("✅ Default admin user created: username=admin, password=admin123");
    } else {
      console.log("✅ Default admin user already exists");
    }

    // Final verification - check all created tables
    console.log("🔍 Verifying created tables...");
    const finalTables = await db.execute(sql`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);

    const expectedTables = [
      'accessories', 'activities', 'assets', 'bitlocker_keys', 'components', 
      'consumable_assignments', 'consumables', 'discovered_hosts', 'it_equipment', 
      'it_equipment_assignments', 'license_assignments', 'licenses', 'settings', 
      'system_settings', 'users', 'vm_inventory', 'vm_monitoring', 'vms', 
      'zabbix_settings', 'zabbix_subnets'
    ];

    console.log("📊 Tables now in database:", finalTables.rows?.map(t => t.table_name) || []);
    console.log("📋 Expected tables:", expectedTables);

    // Count rows in users table to verify it's working
    const userCount = await db.execute(sql`SELECT COUNT(*) as count FROM users`);
    console.log("👥 Users in database:", userCount.rows?.[0]?.count || 0);

    console.log("✅ Database migrations completed successfully!");

  } catch (error) {
    console.error("❌ Migration failed:", error);
    console.error("📍 Error details:", {
      message: error.message,
      code: error.code,
      detail: error.detail
    });
    throw error;
  }
}