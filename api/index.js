const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

// Supabase Connection initialization
const supabaseUrl = process.env.SUPABASE_URL || "";
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

if (!supabaseUrl || !supabaseKey) {
    console.error("⚠️ SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables are missing!");
}

const supabase = createClient(supabaseUrl, supabaseKey);

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
            return res.status(404).json({ success: false, error: "License not found or invalid." });
        }

        if (device.status === 'Blocked') {
            return res.status(403).json({ success: false, error: "This license key has been deactivated." });
        }

        // Binds device ID to enforce single concurrent device rule
        if (device.registered_device_id && device.registered_device_id !== deviceId) {
            return res.status(400).json({ 
                success: false, 
                error: "License already registered on another device. Please reset via admin console." 
            });
        }

        if (!device.registered_device_id) {
            const { error: updateErr } = await supabase
                .from('licenses')
                .update({ registered_device_id: deviceId, last_active: new Date() })
                .eq('key', key.trim());
            
            if (updateErr) throw updateErr;
        } else {
            await supabase
                .from('licenses')
                .update({ last_active: new Date() })
                .eq('key', key.trim());
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
 * 3. Log SMS Endpoint: Invoked by the app client upon intercepting SMS
 */
app.post('/api/sms/log', async (req, res) => {
    const { key, sender, message, timestamp, deviceLabel, simSlot, deviceId } = req.body;

    if (!key || !sender || !message) {
        return res.status(400).json({ success: false, error: "Missing required logging payload data." });
    }

    try {
        // Enforce active status before writing to database
        const { data: device, error: devErr } = await supabase
            .from('licenses')
            .select('*')
            .eq('key', key.trim())
            .single();

        if (devErr || !device) {
            return res.status(404).json({ success: false, error: "License signature mismatch." });
        }

        if (device.status === 'Blocked') {
            return res.status(403).json({ success: false, error: "Terminal blocked: Interception suspended." });
        }

        if (deviceId && device.registered_device_id && device.registered_device_id !== deviceId) {
            return res.status(400).json({ success: false, error: "Interception mismatch: Bound Device mismatch." });
        }

        // Fetch Filtering configuration settings
        const { data: config } = await supabase
            .from('global_config')
            .select('*')
            .eq('id', 'main_config')
            .single();

        let allowed = true;
        if (config) {
            const mode = config.filter_mode;
            const target = (config.target_value || "").toLowerCase().trim();

            if (mode === 'ALLOW_ONLY' && target) {
                const keywords = target.split(",").map(k => k.trim()).filter(Boolean);
                allowed = keywords.some(kw => message.toLowerCase().includes(kw) || sender.toLowerCase().includes(kw));
            } else if (mode === 'BLOCK_LIST' && target) {
                const keywords = target.split(",").map(k => k.trim()).filter(Boolean);
                allowed = !keywords.some(kw => message.toLowerCase().includes(kw) || sender.toLowerCase().includes(kw));
            }
        }

        if (!allowed) {
            return res.json({ success: true, filtered: true, message: "Ignored: SMS filtered out by Server security rules." });
        }

        // Log the message
        const { error: logErr } = await supabase
            .from('message_logs')
            .insert({
                license_key: key.trim(),
                sender: sender.trim(),
                message: message.trim(),
                device_label: deviceLabel || "Terminal Node",
                sim_slot: simSlot || "Unknown",
                received_at: timestamp ? new Date(timestamp) : new Date()
            });

        if (logErr) throw logErr;

        return res.json({ success: true, filtered: false });
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * 4. Admin API: Verify admin PIN code
 */
app.post('/api/admin/verify', async (req, res) => {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ success: false, error: "PIN is required." });

    try {
        const { data: config } = await supabase
            .from('global_config')
            .select('global_pin')
            .eq('id', 'main_config')
            .single();

        const globalPin = config ? config.global_pin : "7860";
        if (pin.trim() === globalPin.trim()) {
            return res.json({ success: true });
        } else {
            return res.status(401).json({ success: false, error: "Invalid credentials." });
        }
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
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
        const generatedKey = `KEY-${sanitizedName}-${randomNum}`;
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
    if (!key || !status) return res.status(400).json({ error: "Missing parameters." });

    try {
        const { error } = await supabase
            .from('licenses')
            .update({ status })
            .eq('key', key.trim());

        if (error) throw error;
        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/**
 * 7. Admin API: Reset bound device ID
 */
app.post('/api/admin/reset-device', adminAuth, async (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: "Key is required." });

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
 * 8. Admin API: Update global filtering rules
 */
app.post('/api/admin/rules', adminAuth, async (req, res) => {
    const { mode, target } = req.body;
    try {
        const { error } = await supabase
            .from('global_config')
            .update({ filter_mode: mode, target_value: target })
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

        // Fetch latest logs
        const { data: messages } = await supabase
            .from('message_logs')
            .select('*')
            .order('received_at', { ascending: false })
            .limit(100);

        // Fetch global rules config
        const { data: config } = await supabase
            .from('global_config')
            .select('*')
            .eq('id', 'main_config')
            .single();

        return res.json({
            success: true,
            devices: licenses || [],
            messages: messages || [],
            filterMode: config ? config.filter_mode : "ALL",
            targetValue: config ? config.target_value : ""
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

/**
 * Serving HTML Dashboard
 */
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMS Central Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .code-font { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
    <!-- Authorization Lock Screen -->
    <div id="authOverlay" class="fixed inset-0 bg-slate-950 flex flex-col items-center justify-center z-50 p-4">
        <div class="w-full max-w-md p-8 bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl space-y-6 text-center">
            <div class="space-y-2">
                <span class="text-4xl">🔐</span>
                <h1 class="text-2xl font-bold tracking-tight text-white">Console Locked</h1>
                <p class="text-sm text-slate-400">Enter Admin PIN to access the SMS Gateway Console</p>
            </div>
            <div class="space-y-4">
                <input type="password" id="authPin" placeholder="••••" class="w-full text-center py-3 bg-slate-950 border border-slate-800 rounded-2xl text-2xl tracking-widest text-indigo-400 outline-none focus:border-indigo-500 transition-all">
                <button onclick="submitAuth()" class="w-full py-3 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white font-semibold rounded-2xl transition-all shadow-lg shadow-indigo-600/20">
                    Unlock Console
                </button>
            </div>
        </div>
    </div>

    <!-- Live Console Dashboard -->
    <div id="dashboard" class="hidden">
        <!-- Top Nav -->
        <header class="border-b border-slate-900 bg-slate-900/40 backdrop-blur-md sticky top-0 z-30">
            <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold tracking-tight text-white mt-1">SMS Console Hub</h1>
                    <p class="text-xs text-slate-500">Secure real-time terminal sync and message dispatch log</p>
                </div>
                <button onclick="logout()" class="px-4 py-2 bg-slate-900 hover:bg-slate-850 text-slate-300 font-bold text-xs rounded-xl border border-slate-800 transition-all">
                    Lock Console
                </button>
            </div>
        </header>

        <!-- Main Body Grid -->
        <main class="max-w-7xl mx-auto px-6 py-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
            <!-- Left Panel: Rules, Terminal Creator & Settings -->
            <div class="space-y-8 lg:col-span-1">
                <!-- System Filtering Rules -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>🛡️</span> Security Routing Rules
                    </h2>
                    <div class="space-y-3 text-xs">
                        <label class="block text-xs font-semibold text-slate-400 uppercase">Routing Action Mode</label>
                        <select id="filterMode" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white outline-none focus:border-indigo-500">
                            <option value="ALL">Forward All incoming SMS</option>
                            <option value="ALLOW_ONLY">Allow only specific text keywords (OTP, Bank...)</option>
                            <option value="BLOCK_LIST">Block specific keywords or senders</option>
                        </select>
                        
                        <label class="block text-xs font-semibold text-slate-400 uppercase mt-2">Keywords / Target (Comma Separated)</label>
                        <input type="text" id="targetValue" placeholder="OTP, Verification, Pay" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white outline-none focus:border-indigo-500">
                        
                        <button onclick="saveRules()" class="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition-all">
                            Save Security Profile
                        </button>
                    </div>
                </div>

                <!-- Generate Terminal Node License -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>🆕</span> Create Terminal Node
                    </h2>
                    <div class="space-y-3 text-xs">
                        <label class="block text-xs font-semibold text-slate-400 uppercase">Device Label / Owner Name</label>
                        <input type="text" id="genName" placeholder="e.g. John's Pixel 8" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white outline-none focus:border-indigo-500">
                        
                        <label class="block text-xs font-semibold text-slate-400 uppercase mt-2">Device Console Lock PIN (Optional)</label>
                        <input type="text" id="genPin" placeholder="e.g. 7860" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white outline-none focus:border-indigo-500">
                        
                        <button onclick="generateLicense()" class="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-xl text-sm transition-all">
                            Generate Registration Key
                        </button>
                    </div>
                </div>

                <!-- Change Master Admin Web Console PIN -->
                <div class="p-6 bg-slate-900/40 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-lg font-bold text-white flex items-center gap-2">
                        <span>🔒</span> Change Admin Console PIN
                    </h2>
                    <div class="space-y-3 text-xs">
                        <label class="block text-xs font-semibold text-slate-400 uppercase">New Master Dashboard PIN</label>
                        <input type="password" id="newGlobalPin" placeholder="Enter at least 4 digits" class="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-white outline-none focus:border-indigo-500">
                        
                        <button onclick="updateGlobalPin()" class="w-full py-2 bg-indigo-600/30 hover:bg-indigo-600 text-indigo-300 hover:text-white font-semibold rounded-xl text-sm transition-all border border-indigo-500/20">
                            Apply New Master PIN
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
                            <!-- Populated dynamically -->
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
                <!-- Registered Devices Grid -->
                <div>
                    <h3 class="text-lg font-bold text-white mb-4">🖥️ Active Registered Terminal Nodes</h3>
                    <div id="devicesList" class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <!-- Populated dynamically -->
                    </div>
                </div>

                <!-- Live Message dispatch log stream -->
                <div>
                    <h3 class="text-lg font-bold text-white mb-4">📜 Real-time SMS Forwarding Logs</h3>
                    <div id="messageStream" class="space-y-4 max-h-[700px] overflow-y-auto pr-2">
                        <!-- Populated dynamically -->
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let ADMIN_TOKEN = localStorage.getItem('sms_admin_pin') || '';
        if (ADMIN_TOKEN) {
            document.getElementById('authOverlay').classList.add('hidden');
            document.getElementById('dashboard').classList.remove('hidden');
            fetchData();
        }

        async function submitAuth() {
            const pin = document.getElementById('authPin').value;
            if (!pin) return alert("Please enter your console unlock security PIN!");
            try {
                const res = await fetch('/api/admin/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pin })
                });
                if (res.ok) {
                    ADMIN_TOKEN = pin;
                    localStorage.setItem('sms_admin_pin', ADMIN_TOKEN);
                    document.getElementById('authOverlay').classList.add('hidden');
                    document.getElementById('dashboard').classList.remove('hidden');
                    fetchData();
                } else {
                    alert("Invalid signature security credentials.");
                }
            } catch(e) {
                alert("Error connecting to server instance: " + e);
            }
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
                        .map(dev => `<option value="\${dev.key}">\${dev.device_name} (\${dev.key})</option>`)
                        .join('') || '<option value="">No Active Nodes Registered</option>';
                    
                    // Restore previous selection if still exists
                    if (selectedVal && tamperSelect.querySelector(`option[value="\${selectedVal}"]`)) {
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
            
            const script = `// ==UserScript==
// @name         SMS Gateway OTP Sync
// @namespace    http://tampermonkey.net/
// @version      1.1
// @description  Fetch SMS messages from SMS Gateway Vercel API and use them.
// @author       Admin
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @connect      \${hostname}
// ==/UserScript==

(function() {
    'use strict';

    // Configured for Terminal Node: \${key}
    const LICENSE_KEY = "\${key}";
    const API_URL = "\${baseUrl}/api/messages/latest?key=" + LICENSE_KEY + "&limit=1";

    console.log("[SMS Hub] Tampermonkey Polling Active. Key:", LICENSE_KEY);

    let lastFetchedMsgId = "";

    async function checkForNewMessages() {
        GM_xmlhttpRequest({
            method: "GET",
            url: API_URL,
            onload: function(response) {
                try {
                    const data = JSON.parse(response.responseText);
                    if (data.success && data.messages && data.messages.length > 0) {
                        const latestMsg = data.messages[0];
                        if (latestMsg.id !== lastFetchedMsgId) {
                            lastFetchedMsgId = latestMsg.id;
                            console.log("🎉 New SMS Intercepted via Tampermonkey:", latestMsg);
                            
                            // Visual Notification on the Web Page
                            showVisualNotification(latestMsg);
                        }
                    }
                } catch(e) {
                    console.error("[SMS Hub] Error parsing response:", e);
                }
            }
        });
    }

    // Display a beautiful visual alert popup on top of the web page
    function showVisualNotification(msg) {
        const div = document.createElement('div');
        div.style.position = 'fixed';
        div.style.bottom = '20px';
        div.style.right = '20px';
        div.style.backgroundColor = '#1e1b4b';
        div.style.border = '1px solid #4f46e5';
        div.style.color = '#e0e7ff';
        div.style.padding = '16px';
        div.style.borderRadius = '12px';
        div.style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.5)';
        div.style.zIndex = '999999';
        div.style.fontFamily = 'system-ui, -apple-system, sans-serif';
        div.style.maxWidth = '350px';
        div.style.transition = 'all 0.3s ease';
        
        div.innerHTML = \\\`
            <div style="font-weight: bold; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
                <span>📱 SMS Received</span>
                <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: #818cf8; cursor: pointer; font-size: 16px;">×</button>
            </div>
            <div style="font-size: 11px; color: #818cf8; margin-bottom: 6px;">From: <b>\\\\\\\${msg.sender}</b></div>
            <div style="font-size: 13px; font-family: monospace; background: #090514; padding: 8px; border-radius: 6px; border: 1px solid #312e81; word-break: break-all;">
                \\\\\\\${msg.message}
            </div>
            <div style="margin-top: 8px; text-align: right;">
                <button onclick="navigator.clipboard.writeText(\\\\\\\`\\\\\\\${msg.message}\\\\\\\`); alert(\\\\\\\'SMS copied to clipboard!\\\\\\\');" style="background: #4f46e5; border: none; color: white; padding: 4px 10px; border-radius: 6px; font-size: 11px; cursor: pointer; font-weight: 600;">Copy Text</button>
            </div>
        \\\`;
        document.body.appendChild(div);
        
        // Auto remove after 20 seconds
        setTimeout(() => { if (div.parentNode) div.remove(); }, 20000);
    }

    // Poll every 4 seconds
    setInterval(checkForNewMessages, 4000);
})();`;

            document.getElementById('tamperCode').value = script;
        }

        function copyTamperScript() {
            const code = document.getElementById('tamperCode');
            code.select();
            document.execCommand('copy');
            alert("🎉 Tampermonkey Script copied to clipboard!\\n\\nPaste it into your Tampermonkey Dashboard (Create a new script, replace everything, and save).");
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
                    alert(\`🎉 KEY CREATED!\\n\\nKey: \${data.license.key}\\nPIN: \${data.license.console_pin}\`);
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
                container.innerHTML = \`<div class="text-slate-500 text-sm italic col-span-2 text-center py-4">No active nodes registered.</div>\`;
                return;
            }

            container.innerHTML = devices.map(dev => {
                const isBlocked = dev.status === 'Blocked';
                const boundStatus = dev.registered_device_id 
                    ? \`<div class="flex items-center justify-between text-[11px] bg-slate-950 p-2 rounded border border-slate-800 mt-2">
                         <span class="text-amber-400 font-medium">📱 Device Registered</span>
                         <button onclick="resetDevice('\${dev.key}')" class="text-[10px] bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 font-bold px-2 py-0.5 rounded border border-amber-500/20 transition-all">
                           Reset Binding
                         </button>
                       </div>\`
                    : \`<div class="text-[11px] text-emerald-400 font-medium mt-2">📱 Status: Available for Registration</div>\`;

                return \`
                    <div class="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
                        <div class="flex items-center justify-between">
                            <span class="px-2.5 py-0.5 rounded-full text-xs font-bold \${isBlocked ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}">
                                \${dev.status}
                            </span>
                            <button onclick="toggleStatus('\${dev.key}', '\${dev.status}')" class="text-xs text-indigo-400 hover:text-indigo-300 font-bold transition-colors">
                                \${isBlocked ? 'Activate' : 'Block Key'}
                            </button>
                        </div>
                        
                        <div>
                            <div class="text-xs text-slate-500 font-medium uppercase tracking-wider">Device ID / Name</div>
                            <div class="font-bold text-white text-sm">\${dev.device_name}</div>
                        </div>

                        <div>
                            <div class="text-xs text-slate-500 font-medium uppercase tracking-wider">Registration Key</div>
                            <div class="code-font text-xs font-bold text-indigo-300 mt-1 select-all">\${dev.key}</div>
                        </div>

                        \${boundStatus}

                        <div class="text-[10px] text-slate-500 pt-2 border-t border-slate-800/60">
                            Last active: \${new Date(dev.last_active).toLocaleString()}
                        </div>
                    </div>
                \`;
            }).join('');
        }

        function renderMessages(messages) {
            const container = document.getElementById('messageStream');
            if (!messages || messages.length === 0) {
                container.innerHTML = \`<div class="text-slate-500 text-sm italic py-8 text-center bg-slate-950/20 rounded-xl border border-dashed border-slate-800">No logs found. Ensure Gateway client is forwarding messages.</div>\`;
                return;
            }

            container.innerHTML = messages.map(msg => \`
                <div class="p-4 bg-slate-950 border border-slate-900 rounded-xl space-y-2 hover:border-slate-800 transition-all">
                    <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <div class="flex items-center gap-1.5 font-bold text-white">
                            <span class="text-indigo-400">\${msg.sender}</span>
                            <span class="text-slate-600">→</span>
                            <span class="text-indigo-300">\${msg.device_label}</span>
                            <span class="bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded text-[10px] text-slate-400">\${msg.sim_slot}</span>
                        </div>
                        <div class="text-slate-500">\${new Date(msg.received_at).toLocaleTimeString()}</div>
                    </div>
                    <p class="text-sm text-slate-300 code-font break-words bg-slate-900/60 p-2 rounded-lg border border-slate-800/40">\${msg.message}</p>
                </div>
            \`).join('');
        }

        // Auto Poll Live Data every 15 seconds
        setInterval(fetchData, 15000);
    </script>
</body>
</html>
    `);
});

// Start Express Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app;