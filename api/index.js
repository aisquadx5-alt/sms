const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || '';

let supabase = null;
if (supabaseUrl && supabaseKey) {
    try {
        supabase = createClient(supabaseUrl, supabaseKey);
    } catch (err) {
        console.error("⚠️ Failed to initialize Supabase client:", err);
    }
} else {
    console.error("⚠️ SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables are missing!");
}

// Global Middleware to prevent crashes on all API endpoints if Supabase is not connected
app.use('/api', (req, res, next) => {
    if (!supabase) {
        return res.status(503).json({
            success: false,
            error: "Database Connection Error: Supabase credentials (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY) are missing or invalid in your Server Environment Variables. Please set them in your Vercel Project Settings."
        });
    }
    next();
});

// Shared Admin Authorization Middleware
const adminAuth = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    
    // Retrieve global admin pin
    const { data: config } = await supabase
        .from('global_config')
        .select('global_pin')
        .eq('id', 'main_config')
        .single();
        
    const globalPin = config ? config.global_pin : "7860";

    if (authHeader && authHeader.trim() === globalPin.trim()) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized: Invalid admin PIN." });
    }
};

/**
 * 1. Activation Endpoint: Validates license key and binds Device UUID
 */
app.post('/api/license/activate', async (req, res) => {
    const { key, deviceId } = req.body;
    if (!key) {
        return res.status(400).json({ success: false, error: "License key is required." });
    }

    try {
        const { data: device, error } = await supabase
            .from('licenses')
            .select('*')
            .eq('key', key.trim())
            .single();

        if (error || !device) {
            return res.status(404).json({ success: false, error: "License not found." });
        }

        if (device.status === 'Blocked') {
            return res.status(403).json({ success: false, error: "This license key has been deactivated." });
        }

        // Enforce one device per license key
        let updatedDeviceId = device.registered_device_id;
        if (deviceId) {
            if (device.registered_device_id && device.registered_device_id !== deviceId) {
                return res.status(400).json({ 
                    success: false, 
                    error: "License already registered on another device. Please reset via admin console." 
                });
            }
            if (!device.registered_device_id) {
                updatedDeviceId = deviceId;
                await supabase
                    .from('licenses')
                    .update({ registered_device_id: deviceId, last_active: new Date() })
                    .eq('key', key.trim());
            } else {
                await supabase
                    .from('licenses')
                    .update({ last_active: new Date() })
                    .eq('key', key.trim());
            }
        }

        // Fetch current global filtering rules
        const { data: config } = await supabase
            .from('global_config')
            .select('*')
            .eq('id', 'main_config')
            .single();

        return res.status(200).json({
            success: true,
            key: device.key,
            deviceName: device.device_name,
            consolePin: device.console_pin,
            status: device.status,
            filterMode: config ? config.filter_mode : "ALL",
            targetValue: config ? config.target_value : ""
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * 2. Status Handshake Loop: Periodically called by the app
 */
app.post('/api/license/status', async (req, res) => {
    const { key, deviceId } = req.body;
    if (!key) {
        return res.status(400).json({ success: false, error: "License key is required." });
    }

    try {
        const { data: device, error } = await supabase
            .from('licenses')
            .select('*')
            .eq('key', key.trim())
            .single();

        if (error || !device) {
            return res.status(404).json({ success: false, error: "License not found." });
        }

        if (deviceId && device.registered_device_id && device.registered_device_id !== deviceId) {
            return res.status(400).json({ success: false, error: "Access denied: Device ID mismatch." });
        }

        // Update heartbeat
        await supabase
            .from('licenses')
            .update({ last_active: new Date() })
            .eq('key', key.trim());

        const { data: config } = await supabase
            .from('global_config')
            .select('*')
            .eq('id', 'main_config')
            .single();

        return res.status(200).json({
            success: true,
            status: device.status,
            consolePin: device.console_pin,
            filterMode: config ? config.filter_mode : "ALL",
            targetValue: config ? config.target_value : ""
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * 3. SMS Gateway Stream: Receive SMS logs from active devices
 */
app.post('/api/sms/incoming', async (req, res) => {
    const { key, deviceId, message, sender, timestamp, simSlot, deviceLabel } = req.body;

    if (!key || !message || !sender) {
        return res.status(400).json({ success: false, error: "Missing required properties." });
    }

    try {
        const { data: device, error } = await supabase
            .from('licenses')
            .select('*')
            .eq('key', key.trim())
            .single();

        if (error || !device) {
            return res.status(404).json({ success: false, error: "License key unregistered." });
        }

        if (device.status === 'Blocked') {
            return res.status(403).json({ success: false, error: "Access blocked: License key is disabled." });
        }

        if (deviceId && device.registered_device_id && device.registered_device_id !== deviceId) {
            return res.status(400).json({ success: false, error: "Device UUID mismatch." });
        }

        const msgId = 'msg_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
        
        await supabase
            .from('message_logs')
            .insert({
                id: msgId,
                sender: sender,
                message: message,
                timestamp: timestamp || Date.now(),
                device_label: deviceLabel || device.device_name,
                sim_slot: simSlot || 'SIM 1',
                license_key: key.trim(),
                status: 'Forwarded'
            });

        // Update active device heartbeat
        await supabase
            .from('licenses')
            .update({ last_active: new Date() })
            .eq('key', key.trim());

        return res.json({ success: true, messageId: msgId });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * 4. Admin API: Verify admin PIN code
 */
app.post('/api/admin/verify', async (req, res) => {
    const { pin } = req.body;
    if (!pin) {
        return res.status(400).json({ error: "PIN is required." });
    }

    try {
        const { data: config } = await supabase
            .from('global_config')
            .select('global_pin')
            .eq('id', 'main_config')
            .single();

        const globalPin = config ? config.global_pin : "7860";

        if (pin.trim() === globalPin.trim()) {
            return res.json({ success: true, token: globalPin.trim() });
        } else {
            return res.status(401).json({ success: false, error: "Incorrect PIN number." });
        }
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 5. Admin API: Generate custom license
 */
app.post('/api/admin/generate', adminAuth, async (req, res) => {
    const { deviceName, customPin } = req.body;
    if (!deviceName) {
        return res.status(400).json({ error: "Device label/name is required." });
    }

    try {
        const sanitizedName = deviceName.replace(/[^a-zA-Z0-9]/g, "").toUpperCase().substring(0, 8);
        const randomNum = Math.floor(1000 + Math.random() * 9000);
        const generatedKey = 'KEY-' + sanitizedName + '-' + randomNum;
        const pin = customPin ? customPin.toString().substring(0, 6) : "7860";

        const { data, error } = await supabase
            .from('licenses')
            .insert({
                key: generatedKey,
                device_name: deviceName.trim(),
                status: 'Active',
                console_pin: pin
            })
            .select()
            .single();

        if (error) throw error;

        return res.json({ success: true, license: data });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 6. Admin API: Toggle license status
 */
app.post('/api/admin/status-toggle', adminAuth, async (req, res) => {
    const { key, status } = req.body;
    if (!key || !status) {
        return res.status(400).json({ error: "Key and status parameters are required." });
    }

    try {
        const { error } = await supabase
            .from('licenses')
            .update({ status: status })
            .eq('key', key.trim());

        if (error) throw error;
        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 7. Admin API: Reset device ID
 */
app.post('/api/admin/reset-device', adminAuth, async (req, res) => {
    const { key } = req.body;
    if (!key) {
        return res.status(400).json({ error: "Missing key parameter." });
    }

    try {
        const { error } = await supabase
            .from('licenses')
            .update({ registered_device_id: null })
            .eq('key', key.trim());

        if (error) throw error;
        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 8. Admin API: Update dynamic filter rules
 */
app.post('/api/admin/rules', adminAuth, async (req, res) => {
    const { mode, target } = req.body;
    if (!mode) {
        return res.status(400).json({ error: "Filter mode is required." });
    }

    try {
        const { error } = await supabase
            .from('global_config')
            .update({ filter_mode: mode, target_value: target || "" })
            .eq('id', 'main_config');

        if (error) throw error;
        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 9. Admin API: Change primary master PIN
 */
app.post('/api/admin/global-pin', adminAuth, async (req, res) => {
    const { pin } = req.body;
    if (!pin || pin.trim().length < 4) {
        return res.status(400).json({ error: "Global Master PIN must be at least 4 digits long." });
    }

    try {
        const { error } = await supabase
            .from('global_config')
            .update({ global_pin: pin.trim() })
            .eq('id', 'main_config');

        if (error) throw error;
        return res.json({ success: true, newPin: pin.trim() });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 10. Admin Dashboard Core Data Sync
 */
app.get('/api/admin/dashboard-data', adminAuth, async (req, res) => {
    try {
        // Fetch all licenses
        const { data: licenses } = await supabase
            .from('licenses')
            .select('*')
            .order('last_active', { ascending: false });

        // Fetch latest 50 SMS messages
        const { data: messageLogs } = await supabase
            .from('message_logs')
            .select('*')
            .order('received_at', { ascending: false })
            .limit(50);

        // Fetch current global filter/pin setup
        const { data: config } = await supabase
            .from('global_config')
            .select('*')
            .eq('id', 'main_config')
            .single();

        return res.json({
            success: true,
            devices: licenses || [],
            messages: messageLogs || [],
            filterMode: config ? config.filter_mode : 'ALL',
            targetValue: config ? config.target_value : '',
            globalPin: config ? config.global_pin : '7860'
        });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 11. SMS Retrieval API: Securely retrieve the latest received messages for a given license key.
 * This can be used by external integrations like Tampermonkey, scripts, or systems.
 * Usage: GET /api/messages/latest?key=YOUR_LICENSE_KEY&limit=5
 */
app.get('/api/messages/latest', async (req, res) => {
    const { key, limit } = req.query;

    if (!key) {
        return res.status(400).json({ success: false, error: "License key is required." });
    }

    try {
        // Validate license
        const { data: device, error: devErr } = await supabase
            .from('licenses')
            .select('*')
            .eq('key', key.trim())
            .single();

        if (devErr || !device) {
            return res.status(404).json({ success: false, error: "License not found or invalid key." });
        }

        if (device.status === 'Blocked') {
            return res.status(403).json({ success: false, error: "Access blocked: This license key has been deactivated." });
        }

        // Parse optional limit
        const limitCount = parseInt(limit, 10) || 5;
        const finalLimit = Math.min(Math.max(limitCount, 1), 50);

        // Fetch latest messages for this key
        const { data: messages, error: msgErr } = await supabase
            .from('message_logs')
            .select('*')
            .eq('license_key', key.trim())
            .order('received_at', { ascending: false })
            .limit(finalLimit);

        if (msgErr) throw msgErr;

        return res.json({
            success: true,
            deviceName: device.device_name,
            messages: messages || []
        });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

// Dashboard HTML as a static string (no template literals to avoid nesting issues)
const DASHBOARD_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMS Gateway Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Space Grotesk', sans-serif;
            background: radial-gradient(circle at top right, #0f172a, #020617);
        }
        .code-font {
            font-family: 'JetBrains Mono', monospace;
        }
    </style>
</head>
<body class="text-slate-100 min-h-screen">
    <!-- DB Warning Banner -->
    <div id="dbWarning"></div>
    <!-- Main Outer Container -->
    <div id="authContainer" class="fixed inset-0 bg-slate-950/95 flex items-center justify-center z-50">
        <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl w-full max-w-md shadow-2xl space-y-6">
            <div class="text-center space-y-2">
                <div class="inline-flex p-3 bg-indigo-500/10 text-indigo-400 rounded-2xl border border-indigo-500/20 mb-2">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                </div>
                <h1 class="text-2xl font-bold tracking-tight text-white">Console Locked</h1>
                <p class="text-sm text-slate-400">Enter Admin PIN to access the SMS Gateway Console</p>
            </div>
            
            <div class="space-y-4">
                <input type="password" id="pinInput" placeholder="••••" class="w-full text-center tracking-widest text-2xl font-bold py-3 bg-slate-950 border border-slate-800 rounded-xl focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-white placeholder-slate-700 outline-none transition-all">
                <button onclick="login()" class="w-full bg-indigo-600 hover:bg-indigo-500 active:scale-[0.98] text-white font-semibold py-3 px-4 rounded-xl transition-all shadow-lg shadow-indigo-600/20">
                    Verify & Unlock
                </button>
            </div>
            <div id="authError" class="text-red-400 text-sm text-center font-medium hidden">❌ Invalid PIN code. Please try again.</div>
        </div>
    </div>

    <!-- Live Console Dashboard -->
    <div id="dashboard" class="hidden max-w-7xl mx-auto px-4 py-8 space-y-8">
        <!-- Top Bar -->
        <header class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
            <div>
                <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                    <span class="text-xs font-semibold tracking-wider text-emerald-400 uppercase">Gateway Active</span>
                </div>
                <h1 class="text-3xl font-bold tracking-tight text-white mt-1">SMS Console Hub</h1>
                <p class="text-slate-400 text-sm">Supabase & Vercel serverless persistence engine</p>
            </div>
            <div class="flex items-center gap-3">
                <button onclick="logout()" class="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-xl text-sm font-semibold text-slate-300 transition-all">
                    Lock Console
                </button>
                <button onclick="fetchData()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-xl text-sm font-semibold text-white transition-all">
                    Refresh Logs
                </button>
            </div>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Left Panel: Configurations & Actions -->
            <div class="space-y-8 lg:col-span-1">
                <!-- Generator Card -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>🔑</span> Generate License Key
                    </h2>
                    <div class="space-y-3">
                        <input type="text" id="genName" placeholder="e.g. Aslam-OPPO" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 outline-none focus:border-indigo-500 transition-all">
                        <input type="text" id="genPin" placeholder="Custom Device PIN (Optional)" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 outline-none focus:border-indigo-500 transition-all">
                        <button onclick="generateLicense()" class="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition-all">
                            Create License Profile
                        </button>
                    </div>
                </div>

                <!-- Global Rules Card -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>⚙️</span> SMS Filter Rules
                    </h2>
                    <div class="space-y-3">
                        <label class="block text-xs font-semibold text-slate-400 uppercase">Routing Rule</label>
                        <select id="filterMode" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white outline-none focus:border-indigo-500">
                            <option value="ALL">Forward All Messages</option>
                            <option value="SENDER">Filter by Sender Address</option>
                            <option value="KEYWORD">Filter by Message Keyword</option>
                        </select>
                        <input type="text" id="targetValue" placeholder="e.g. Google, OTP, +92300" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 outline-none focus:border-indigo-500 transition-all">
                        <button onclick="saveRules()" class="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition-all">
                            Apply Routing Rule
                        </button>
                    </div>
                </div>

                <!-- Global Master Pin Setup -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>🔒</span> Change Admin Console PIN
                    </h2>
                    <div class="space-y-3">
                        <input type="password" id="newGlobalPin" placeholder="Enter New Master PIN" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-600 outline-none focus:border-indigo-500 transition-all">
                        <button onclick="updateGlobalPin()" class="w-full py-2 bg-amber-600 hover:bg-amber-500 text-white font-semibold rounded-xl text-sm transition-all">
                            Update Master PIN
                        </button>
                    </div>
                </div>

                <!-- Tampermonkey Integration -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>🐒</span> Tampermonkey Integration
                    </h2>
                    <div class="space-y-3 text-xs text-slate-400 leading-relaxed">
                        <p>Receive SMS/OTPs directly inside your web pages or automated workflows using Tampermonkey!</p>
                        
                        <label class="block text-xs font-semibold text-slate-300 uppercase mt-2">1. Select Registered Node</label>
                        <select id="tamperKeySelect" onchange="updateTampermonkeyScript()" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-sm text-white outline-none focus:border-indigo-500">
                            <option value="">No Active Nodes</option>
                        </select>
                        
                        <label class="block text-xs font-semibold text-slate-300 uppercase mt-2">2. Generated UserScript Code</label>
                        <textarea id="tamperCode" readonly rows="8" class="w-full px-2 py-1.5 bg-slate-950 border border-slate-850 rounded-lg text-[10px] text-indigo-200 font-mono focus:border-indigo-500 transition-all resize-none outline-none select-all"></textarea>
                        
                        <button onclick="copyTamperScript()" class="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition-all">
                            📋 Copy Tampermonkey Script
                        </button>
                    </div>
                </div>
            </div>

            <!-- Right Panel: Registered Devices & Live Streams -->
            <div class="lg:col-span-2 space-y-8">
                <!-- Device Profiles Grid -->
                <div class="space-y-4">
                    <h2 class="text-xl font-bold text-white flex items-center gap-2">
                        <span>📱</span> Terminals Registered
                    </h2>
                    <div id="devicesList" class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <!-- Devices render dynamic -->
                    </div>
                </div>

                <!-- Incoming SMS Streaming log -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <div class="flex items-center justify-between">
                        <h2 class="text-xl font-bold text-white flex items-center gap-2">
                            <span>💬</span> Live Received Messages Log
                        </h2>
                        <span class="text-xs bg-slate-950 px-2.5 py-1 border border-slate-800 rounded-lg text-slate-400">Showing Last 50 Logs</span>
                    </div>

                    <div id="messageStream" class="space-y-3 max-h-[500px] overflow-y-auto pr-2">
                        <!-- Messages render dynamic -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let ADMIN_TOKEN = localStorage.getItem('sms_admin_pin') || '';

        if (ADMIN_TOKEN) {
            document.getElementById('authContainer').classList.add('hidden');
            document.getElementById('dashboard').classList.remove('hidden');
            fetchData();
        }

        async function login() {
            const pin = document.getElementById('pinInput').value;
            try {
                const res = await fetch('/api/admin/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pin })
                });
                const data = await res.json();
                if (data.success) {
                    ADMIN_TOKEN = data.token;
                    localStorage.setItem('sms_admin_pin', ADMIN_TOKEN);
                    document.getElementById('authContainer').classList.add('hidden');
                    document.getElementById('dashboard').classList.remove('hidden');
                    document.getElementById('authError').classList.add('hidden');
                    fetchData();
                } else {
                    showError();
                }
            } catch(e) {
                showError();
            }
        }

        function showError() {
            const err = document.getElementById('authError');
            err.classList.remove('hidden');
        }

        function logout() {
            localStorage.removeItem('sms_admin_pin');
            location.reload();
        }

        let currentDevices = [];

        async function fetchData() {
            try {
                const res = await fetch('/api/admin/dashboard-data', {
                    headers: { 'Authorization': ADMIN_TOKEN }
                });
                if (res.status === 401) return logout();
                const data = await res.json();
                if (data.success) {
                    currentDevices = data.devices || [];
                    renderDevices(data.devices);
                    renderMessages(data.messages);
                    
                    // Populate Tampermonkey dropdown
                    const tamperSelect = document.getElementById('tamperKeySelect');
                    const selectedVal = tamperSelect.value;
                    const activeDevices = (data.devices || []).filter(dev => dev.status === 'Active');
                    
                    tamperSelect.innerHTML = activeDevices
                        .map(dev => '<option value="' + dev.key + '">' + dev.device_name + ' (' + dev.key + ')</option>')
                        .join('') || '<option value="">No Active Nodes Registered</option>';
                    
                    // Restore previous selection if still exists
                    if (selectedVal && tamperSelect.querySelector('option[value="' + selectedVal + '"]')) {
                        tamperSelect.value = selectedVal;
                    }
                    updateTampermonkeyScript();

                    document.getElementById('filterMode').value = data.filterMode;
                    document.getElementById('targetValue').value = data.targetValue;
                }
            } catch(e) {
                console.error("Fetch Data failed: ", e);
            }
        }

        function updateTampermonkeyScript() {
            const key = document.getElementById('tamperKeySelect').value || 'KEY-YOUR-LICENSE-HERE';
            const baseUrl = window.location.origin;
            const hostname = window.location.hostname;
            
            const script = "// ==UserScript==\n" +
                "// @name         SMS Gateway OTP Sync\n" +
                "// @namespace    http://tampermonkey.net/\n" +
                "// @version      1.1\n" +
                "// @description  Fetch SMS messages from SMS Gateway Vercel API and use them.\n" +
                "// @author       Admin\n" +
                "// @match        *://*/*\n" +
                "// @grant        GM_xmlhttpRequest\n" +
                "// @connect      " + hostname + "\n" +
                "// ==/UserScript==\n\n" +
                "(function() {\n" +
                "    'use strict';\n\n" +
                "    // Configured for Terminal Node: " + key + "\n" +
                "    const LICENSE_KEY = \"" + key + "\";\n" +
                "    const API_URL = \"" + baseUrl + "/api/messages/latest?key=\" + LICENSE_KEY + "&limit=1\";\n\n" +
                "    console.log(\"[SMS Hub] Tampermonkey Polling Active. Key:\", LICENSE_KEY);\n\n" +
                "    let lastFetchedMsgId = \"\";\n\n" +
                "    async function checkForNewMessages() {\n" +
                "        GM_xmlhttpRequest({\n" +
                "            method: \"GET\",\n" +
                "            url: API_URL,\n" +
                "            onload: function(response) {\n" +
                "                try {\n" +
                "                    const data = JSON.parse(response.responseText);\n" +
                "                    if (data.success && data.messages && data.messages.length > 0) {\n" +
                "                        const latestMsg = data.messages[0];\n" +
                "                        if (latestMsg.id !== lastFetchedMsgId) {\n" +
                "                            lastFetchedMsgId = latestMsg.id;\n" +
                "                            console.log(\"🎉 New SMS Intercepted via Tampermonkey:\", latestMsg);\n" +
                "                            \n" +
                "                            // Visual Notification on the Web Page\n" +
                "                            showVisualNotification(latestMsg);\n" +
                "                        }\n" +
                "                    }\n" +
                "                } catch(e) {\n" +
                "                    console.error(\"[SMS Hub] Error parsing response:\", e);\n" +
                "                }\n" +
                "            }\n" +
                "        });\n" +
                "    }\n\n" +
                "    // Display a beautiful visual alert popup on top of the web page\n" +
                "    function showVisualNotification(msg) {\n" +
                "        // Remove existing if any\n" +
                "        const existing = document.getElementById('sms-gateway-notification');\n" +
                "        if (existing) existing.remove();\n\n" +
                "        const div = document.createElement('div');\n" +
                "        div.id = 'sms-gateway-notification';\n" +
                "        div.style.position = 'fixed';\n" +
                "        div.style.bottom = '20px';\n" +
                "        div.style.right = '20px';\n" +
                "        div.style.backgroundColor = '#1e1b4b';\n" +
                "        div.style.border = '1px solid #4f46e5';\n" +
                "        div.style.color = '#e0e7ff';\n" +
                "        div.style.padding = '16px';\n" +
                "        div.style.borderRadius = '12px';\n" +
                "        div.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.5)';\n" +
                "        div.style.zIndex = '999999';\n" +
                "        div.style.fontFamily = 'system-ui, -apple-system, sans-serif';\n" +
                "        div.style.maxWidth = '350px';\n" +
                "        div.style.transition = 'all 0.3s ease';\n" +
                "        \n" +
                "        window.copySmsText = function() {\n" +
                "            navigator.clipboard.writeText(msg.message);\n" +
                "            alert(\"SMS copied to clipboard!\");\n" +
                "        };\n\n" +
                "        div.innerHTML = '<div style=\"font-weight: bold; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;\">'\n" +
                "            + '<span>📱 SMS Received</span>'\n" +
                "            + '<button onclick=\"document.getElementById(\'sms-gateway-notification\').remove()\" style=\"background: none; border: none; color: #818cf8; cursor: pointer; font-size: 16px;\">×</button>'\n" +
                "        + '</div>'\n" +
                "        + '<div style=\"font-size: 11px; color: #818cf8; margin-bottom: 6px;\">From: <b>' + msg.sender + '</b></div>'\n" +
                "        + '<div style=\"font-size: 13px; font-family: monospace; background: #090514; padding: 8px; border-radius: 6px; border: 1px solid #312e81; word-break: break-all;\">'\n" +
                "            + msg.message\n" +
                "        + '</div>'\n" +
                "        + '<div style=\"margin-top: 8px; text-align: right;\">'\n" +
                "            + '<button onclick=\"window.copySmsText()\" style=\"background: #4f46e5; border: none; color: white; padding: 4px 10px; border-radius: 6px; font-size: 11px; cursor: pointer; font-weight: 600;\">Copy Text</button>'\n" +
                "        + '</div>';\n" +
                "        document.body.appendChild(div);\n" +
                "        \n" +
                "        // Auto remove after 20 seconds\n" +
                "        setTimeout(() => { if (div.parentNode) div.remove(); }, 20000);\n" +
                "    }\n\n" +
                "    // Poll every 4 seconds\n" +
                "    setInterval(checkForNewMessages, 4000);\n" +
                "})();\n";

            document.getElementById('tamperCode').value = script;
        }

        function copyTamperScript() {
            const code = document.getElementById('tamperCode');
            code.select();
            document.execCommand('copy');
            alert("🎉 Tampermonkey Script copied to clipboard!\n\nPaste it into your Tampermonkey Dashboard (Create a new script, replace everything, and save).");
        }

        async function generateLicense() {
            const name = document.getElementById('genName').value;
            const pin = document.getElementById('genPin').value;
            if (!name) return alert("Please enter device label!");

            try {
                const res = await fetch('/api/admin/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ deviceName: name, customPin: pin })
                });
                const data = await res.json();
                if (data.success) {
                    alert("🎉 KEY CREATED!\n\nKey: " + data.license.key + "\nPIN: " + data.license.console_pin);
                    document.getElementById('genName').value = '';
                    document.getElementById('genPin').value = '';
                    fetchData();
                } else {
                    alert("Failed: " + data.error);
                }
            } catch(e) {
                alert("Error: " + e);
            }
        }

        async function toggleStatus(key, currentStatus) {
            const targetStatus = currentStatus === 'Blocked' ? 'Active' : 'Blocked';
            try {
                const res = await fetch('/api/admin/status-toggle', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ key, status: targetStatus })
                });
                if (res.ok) fetchData();
            } catch(e) {
                alert("Error: " + e);
            }
        }

        async function resetDevice(key) {
            if (!confirm("Are you sure you want to reset the bound Device ID? This allows registration on another phone.")) {
                return;
            }
            try {
                const res = await fetch('/api/admin/reset-device', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ key })
                });
                if (res.ok) {
                    alert("✅ License key reset successfully!");
                    fetchData();
                }
            } catch(e) {
                alert("Error: " + e);
            }
        }

        async function saveRules() {
            const mode = document.getElementById('filterMode').value;
            const target = document.getElementById('targetValue').value;
            try {
                const res = await fetch('/api/admin/rules', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ mode, target })
                });
                if (res.ok) alert("🎉 Rules updated successfully!");
            } catch(e) {
                alert("Error: " + e);
            }
        }

        async function updateGlobalPin() {
            const pin = document.getElementById('newGlobalPin').value;
            if (!pin || pin.length < 4) return alert("PIN must be 4 or more digits!");
            try {
                const res = await fetch('/api/admin/global-pin', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ pin })
                });
                if (res.ok) {
                    alert("🎉 Global Master PIN changed! Re-logging in...");
                    logout();
                }
            } catch(e) {
                alert("Error: " + e);
            }
        }

        function renderDevices(devices) {
            const container = document.getElementById('devicesList');
            if (!devices || devices.length === 0) {
                container.innerHTML = '<div class="text-slate-500 text-sm italic col-span-2 text-center py-4">No active nodes registered.</div>';
                return;
            }

            container.innerHTML = devices.map(dev => {
                const isBlocked = dev.status === 'Blocked';
                const boundStatus = dev.registered_device_id
                    ? '<div class="flex items-center justify-between text-[11px] bg-slate-950 p-2 rounded border border-slate-800 mt-2">\n' +
                      '     <span class="text-amber-400 font-medium">📱 Device Registered</span>\n' +
                      '     <button onclick="resetDevice(\'' + dev.key + '\')" class="text-[10px] bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 font-bold px-2 py-0.5 rounded border border-amber-500/20 transition-all">\n' +
                      '       Reset Binding\n' +
                      '     </button>\n' +
                      '   </div>'
                    : '<div class="text-[11px] text-emerald-400 font-medium mt-2">📱 Status: Available for Registration</div>';

                return '\n' +
                    '                <div class="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3">\n' +
                    '                    <div class="flex items-center justify-between">\n' +
                    '                        <span class="px-2.5 py-0.5 rounded-full text-xs font-bold ' + (isBlocked ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20') + '">\n' +
                    '                            ' + dev.status + '\n' +
                    '                        </span>\n' +
                    '                        <button onclick="toggleStatus(\'' + dev.key + '\', \'' + dev.status + '\')" class="text-xs text-indigo-400 hover:text-indigo-300 font-bold transition-colors">\n' +
                    '                            ' + (isBlocked ? 'Activate' : 'Block Key') + '\n' +
                    '                        </button>\n' +
                    '                    </div>\n' +
                    '                    \n' +
                    '                    <div>\n' +
                    '                        <div class="text-xs text-slate-500 font-medium uppercase tracking-wider">Device ID / Name</div>\n' +
                    '                        <div class="font-bold text-white text-sm">' + dev.device_name + '</div>\n' +
                    '                    </div>\n' +
                    '\n' +
                    '                    <div>\n' +
                    '                        <div class="text-xs text-slate-500 font-medium uppercase tracking-wider">Registration Key</div>\n' +
                    '                        <div class="code-font text-xs font-bold text-indigo-300 mt-1 select-all">' + dev.key + '</div>\n' +
                    '                    </div>\n' +
                    '\n' +
                    boundStatus + '\n' +
                    '\n' +
                    '                    <div class="text-[10px] text-slate-500 pt-2 border-t border-slate-800/60">\n' +
                    '                        Last active: ' + new Date(dev.last_active).toLocaleString() + '\n' +
                    '                    </div>\n' +
                    '                </div>\n';
            }).join('');
        }

        function renderMessages(messages) {
            const container = document.getElementById('messageStream');
            if (!messages || messages.length === 0) {
                container.innerHTML = '<div class="text-slate-500 text-sm italic py-8 text-center bg-slate-950/20 rounded-xl border border-dashed border-slate-800">No logs found. Ensure Gateway client is forwarding messages.</div>';
                return;
            }

            container.innerHTML = messages.map(msg => '\n' +
                '                <div class="p-4 bg-slate-950 border border-slate-900 rounded-xl space-y-2 hover:border-slate-800 transition-all">\n' +
                '                    <div class="flex flex-wrap items-center justify-between gap-2 text-xs">\n' +
                '                        <div class="flex items-center gap-1.5 font-bold text-white">\n' +
                '                            <span class="text-indigo-400">' + msg.sender + '</span>\n' +
                '                            <span class="text-slate-600">→</span>\n' +
                '                            <span class="text-indigo-300">' + msg.device_label + '</span>\n' +
                '                            <span class="bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded text-[10px] text-slate-400">' + msg.sim_slot + '</span>\n' +
                '                        </div>\n' +
                '                        <div class="text-slate-500">' + new Date(msg.received_at).toLocaleTimeString() + '</div>\n' +
                '                    </div>\n' +
                '                    <p class="text-sm text-slate-300 code-font break-words bg-slate-900/60 p-2 rounded-lg border border-slate-800/40">' + msg.message + '</p>\n' +
                '                </div>\n'
            ).join('');
        }

        // Auto Poll Live Data every 15 seconds
        setInterval(fetchData, 15000);
    </script>
</body>
</html>
`;

/**
 * Serving dynamic Dashboard Home page
 */
app.get('/', (req, res) => {
    // Inject Supabase warning banner if needed
    let html = DASHBOARD_HTML;
    if (!supabase) {
        const warningHtml = '<div class="bg-amber-500/15 border-b border-amber-500/30 text-amber-200 px-4 py-3 text-center text-sm font-semibold flex items-center justify-center gap-2 z-[60] relative"><span>⚠️</span><span>Supabase is not configured! Please add your <b>SUPABASE_URL</b> and <b>SUPABASE_SERVICE_ROLE_KEY</b> to your Vercel Project Environment Variables.</span></div>';
        html = html.replace('<div id="dbWarning"></div>', '<div id="dbWarning">' + warningHtml + '</div>');
    }
    res.send(html);
});

// Start Express Server (local development only)
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log('Server is running on port ' + PORT);
    });
}

module.exports = app;