-- Run this SQL query in your Supabase SQL Editor to create the required tables

-- 1. Create licenses table
CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    status TEXT DEFAULT 'Active',
    console_pin TEXT DEFAULT '7860',
    registered_device_id TEXT,
    last_active TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Create messages/logs table
CREATE TABLE IF NOT EXISTS message_logs (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    device_label TEXT DEFAULT 'Unknown Node',
    sim_slot TEXT DEFAULT 'SIM 1',
    license_key TEXT,
    received_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'Forwarded'
);

-- 3. Create global config table (for custom modes and target values)
CREATE TABLE IF NOT EXISTS global_config (
    id TEXT PRIMARY KEY,
    filter_mode TEXT DEFAULT 'ALL',
    target_value TEXT DEFAULT '',
    global_pin TEXT DEFAULT '7860'
);

-- Insert default global config
INSERT INTO global_config (id, filter_mode, target_value, global_pin)
VALUES ('main_config', 'ALL', '', '7860')
ON CONFLICT (id) DO NOTHING;

-- Insert default demo license
INSERT INTO licenses (key, device_name, status, console_pin)
VALUES ('SIG-DEMO-9999', 'Diagnostic Hub Demo', 'Active', '1122')
ON CONFLICT (key) DO NOTHING;
