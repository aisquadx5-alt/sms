const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

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
    try {
        const adminPin = req.headers['authorization'] || '';
        
        // Retrieve global admin pin
        const { data: config } = await supabase
            .from('global_config')
            .select('global_pin')
            .eq('id', 'main_config')
            .single();
            
        const expectedPin = config ? config.global_pin : '7860';
        
        if (adminPin === expectedPin) {
            return next();
        }
        res.status(401).json({ error: "Unauthorized: Invalid admin PIN." });
    } catch (e) {
        res.status(500).json({ error: "Authorization process failed." });
    }
};

// ==========================================
// CLIENT API ENDPOINTS (For Android App Nodes)
// ==========================================

/**
 * 1. Client App Registration / Verification
 */
app.post('/api/licenses/register', async (req, res) => {
    const { key, deviceId, deviceName } = req.body;
    
    if (!key) {
        return res.status(400).json({ error: "License key is required." });
    }
    
    try {
        // Query license from Supabase
        const { data: device, error } = await supabase
            .from('licenses')
            .select('*')
            .eq('key', key)
            .single();
            
        if (error || !device) {
            return res.status(404).json({ error: "License key invalid or expired." });
        }
        
        if (device.status !== 'Active') {
            return res.status(403).json({ error: "This license key has been deactivated by Admin." });
        }
        
        // Handle Device Locking logic
        if (device.registered_device_id && device.registered_device_id !== deviceId) {
            return res.status(400).json({ 
                error: "License already registered on another device. Please reset via admin console." 
            });
        }
        
        // Update device registration & timestamp
        await supabase
            .from('licenses')
            .update({ 
                registered_device_id: deviceId, 
                device_name: deviceName || device.device_name,
                last_active: new Date().toISOString()
            })
            .eq('key', key);
            
        res.json({
            success: true,
            status: "Activated",
            deviceName: deviceName || device.device_name,
            consolePin: device.console_pin,
            message: "Activation credentials authenticated successfully."
        });
    } catch (e) {
        res.status(500).json({ error: "Server database transaction failed." });
    }
});

/**
 * 2. Inbound SMS Forwarding Engine
 */
app.post('/api/messages/intercept', async (req, res) => {
    const { id, sender, message, timestamp, deviceLabel, simSlot, licenseKey } = req.body;
    
    if (!id || !sender || !message || !licenseKey) {
        return res.status(400).json({ error: "Incomplete intercepted message metadata payload." });
    }
    
    try {
        // Confirm license active
        const { data: device } = await supabase
            .from('licenses')
            .select('status, console_pin')
            .eq('key', licenseKey)
            .single();
            
        if (!device || device.status !== 'Active') {
            return res.status(403).json({ error: "Inactive/Deactivated terminal license. Message rejected." });
        }
        
        // Get dynamic message filtering configuration rules
        const { data: config } = await supabase
            .from('global_config')
            .select('*')
            .eq('id', 'main_config')
            .single();
            
        const filterMode = config ? config.filter_mode : 'ALL';
        const targetValue = config ? (config.target_value || '').toLowerCase() : '';
        
        // Evaluate filter rules (ALL, CONTAIN, SENDER)
        let passFilter = true;
        if (filterMode === 'CONTAIN') {
            passFilter = message.toLowerCase().includes(targetValue);
        } else if (filterMode === 'SENDER') {
            passFilter = sender.toLowerCase().includes(targetValue);
        }
        
        if (!passFilter) {
            return res.json({ 
                success: true, 
                status: "Ignored", 
                message: "Payload blocked dynamically by Server-side filtering rules." 
            });
        }
        
        // Save to message logs
        const { error } = await supabase
            .from('message_logs')
            .insert([{
                id,
                sender,
                message,
                timestamp,
                device_label: deviceLabel,
                sim_slot: simSlot,
                license_key: licenseKey,
                status: 'Forwarded'
            }]);
            
        if (error) {
            // If already exists, return success
            if (error.code === '23505') {
                return res.json({ success: true, message: "Duplicate intercepted payload ignored." });
            }
            throw error;
        }
        
        // Keep active timestamp updated
        await supabase
            .from('licenses')
            .update({ last_active: new Date().toISOString() })
            .eq('key', licenseKey);
            
        res.json({
            success: true,
            status: "Forwarded",
            consolePin: device.console_pin,
            message: "SMS Intercepted & Synchronized."
        });
    } catch (e) {
        res.status(500).json({ error: "Intercept logging transactional crash." });
    }
});

/**
 * 3. Client Heartbeat & Deactivation Sync Handshake
 */
app.get('/api/licenses/status', async (req, res) => {
    const { key, deviceId } = req.query;
    
    if (!key) {
        return res.status(400).json({ error: "Terminal License key is required." });
    }
    
    try {
        const { data: device } = await supabase
            .from('licenses')
            .select('*')
            .eq('key', key)
            .single();
            
        if (!device) {
            return res.json({ success: false, status: "Deactivated", error: "Terminal key does not exist." });
        }
        
        if (device.status !== 'Active') {
            return res.json({ success: true, status: "Deactivated" });
        }
        
        // Auto assign device ID if missing
        if (!device.registered_device_id && deviceId) {
            await supabase
                .from('licenses')
                .update({ registered_device_id: deviceId })
                .eq('key', key);
        }
        
        // Record online heartbeat timestamp
        await supabase
            .from('licenses')
            .update({ last_active: new Date().toISOString() })
            .eq('key', key);
            
        res.json({
            success: true,
            status: "Active",
            consolePin: device.console_pin
        });
    } catch (e) {
        res.status(500).json({ error: "Heartbeat transaction crash." });
    }
});

/**
 * 4. Fetch latest messages for a license key (Used by Tampermonkey)
 */
app.get('/api/messages/latest', async (req, res) => {
    const { key, limit } = req.query;
    if (!key) {
        return res.status(400).json({ error: "License key is required." });
    }
    try {
        const { data: messages } = await supabase
            .from('message_logs')
            .select('*')
            .eq('license_key', key)
            .order('timestamp', { ascending: false })
            .limit(parseInt(limit) || 5);
            
        res.json({
            success: true,
            messages: messages || []
        });
    } catch (e) {
        res.status(500).json({ error: "Message fetch failed" });
    }
});

// ==========================================
// ADMIN CONTROL PANEL ENDPOINTS
// ==========================================

/**
 * 1. Admin API: Verify admin PIN code
 */
app.post('/api/admin/verify', async (req, res) => {
    const { pin } = req.body;
    try {
        const { data: config } = await supabase
            .from('global_config')
            .select('global_pin')
            .eq('id', 'main_config')
            .single();
            
        const expectedPin = config ? config.global_pin : '7860';
        if (pin === expectedPin) {
            return res.json({ success: true });
        }
        res.status(401).json({ success: false, error: "Incorrect Admin PIN." });
    } catch (e) {
        res.status(500).json({ error: "Server database crash." });
    }
});

/**
 * 2. Admin API: Generate dynamic new Terminal License Key
 */
app.post('/api/admin/generate', adminAuth, async (req, res) => {
    const { label, customPin } = req.body;
    if (!label) return res.status(400).json({ error: "Device identification label required." });
    
    // Generate unique license parameters
    const rand = Math.floor(1000 + Math.random() * 9000);
    const key = `KEY-${label.toUpperCase().replace(/[^A-Z0-9]/g, '')}-${rand}`;
    const pin = customPin || String(rand);
    
    try {
        const { error } = await supabase
            .from('licenses')
            .insert([{
                key,
                device_name: label,
                status: 'Active',
                console_pin: pin
            }]);
            
        if (error) throw error;
        
        res.json({ success: true, license: { key, console_pin: pin } });
    } catch (e) {
        res.status(500).json({ error: "Failed to generate License Key." });
    }
});

/**
 * 3. Admin API: Deactivate / Reactivate Node Status
 */
app.post('/api/admin/status-toggle', adminAuth, async (req, res) => {
    const { key, status } = req.body;
    if (!key || !status) return res.status(400).json({ error: "Key and status required." });
    
    try {
        await supabase
            .from('licenses')
            .update({ status })
            .eq('key', key);
            
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Failed to change terminal status." });
    }
});

/**
 * 4. Admin API: Reset Device Lockout (Wipe Device ID)
 */
app.post('/api/admin/reset-device', adminAuth, async (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: "Terminal License Key required." });
    
    try {
        await supabase
            .from('licenses')
            .update({ registered_device_id: null })
            .eq('key', key);
            
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Reset transaction crash." });
    }
});

/**
 * 5. Admin API: Modify Global Intercept & Filter Rules
 */
app.post('/api/admin/rules', adminAuth, async (req, res) => {
    const { filterMode, targetValue } = req.body;
    try {
        await supabase
            .from('global_config')
            .update({ filter_mode: filterMode, target_value: targetValue })
            .eq('id', 'main_config');
            
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Update filter config failed." });
    }
});

/**
 * 6. Admin API: Modify Admin Control PIN
 */
app.post('/api/admin/global-pin', adminAuth, async (req, res) => {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ error: "New PIN code required." });
    
    try {
        await supabase
            .from('global_config')
            .update({ global_pin: pin })
            .eq('id', 'main_config');
            
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "PIN updates transaction crash." });
    }
});

/**
 * 7. Admin API: Fetch Master Console Dashboard Data
 */
app.get('/api/admin/dashboard-data', adminAuth, async (req, res) => {
    try {
        const { data: devices } = await supabase
            .from('licenses')
            .select('*')
            .order('last_active', { ascending: false });
            
        const { data: messages } = await supabase
            .from('message_logs')
            .select('*')
            .order('timestamp', { ascending: false })
            .limit(40);
            
        const { data: config } = await supabase
            .from('global_config')
            .select('*')
            .eq('id', 'main_config')
            .single();
            
        res.json({
            success: true,
            devices: devices || [],
            messages: messages || [],
            filterMode: config ? config.filter_mode : 'ALL',
            targetValue: config ? config.target_value : ''
        });
    } catch (e) {
        res.status(500).json({ error: "Console database fetch failure." });
    }
});

// ==========================================
// ADMIN DASHBOARD USER INTERFACE ROUTE (UI)
// ==========================================
app.get('/', async (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMS Central Console</title>
    <!-- Tailwind CSS Engine -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            background-color: #03001e;
            background-image: linear-gradient(135deg, #03001e 0%, #12001b 50%, #050014 100%);
        }
        .scroller::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        .scroller::-webkit-scrollbar-track {
            background: #090514;
        }
        .scroller::-webkit-scrollbar-thumb {
            background: #312e81;
            border-radius: 99px;
        }
    </style>
</head>
<body class="text-slate-100 min-h-screen">
    <!-- DB Warning Banner -->
    \${!supabase ? `
    <div class="bg-amber-500/15 border-b border-amber-500/30 text-amber-200 px-4 py-3 text-center text-sm font-semibold flex items-center justify-center gap-2 z-[60] relative">
        <span>⚠️</span>
        <span>Supabase is not configured! Please add your <b>SUPABASE_URL</b> and <b>SUPABASE_SERVICE_ROLE_KEY</b> to your Vercel Project Environment Variables.</span>
    </div>
    ` : ''}
    <!-- Main Outer Container -->
    <div id="authContainer" class="fixed inset-0 bg-slate-950/95 flex items-center justify-center z-50">
        <div class="bg-slate-900 border border-slate-800 p-8 rounded-2xl w-full max-w-md shadow-2xl space-y-6">
            <div class="text-center space-y-2">
                <div class="inline-flex p-3 bg-indigo-500/10 rounded-full text-indigo-400 text-3xl">📱</div>
                <h1 class="text-2xl font-bold tracking-tight text-white">Console Locked</h1>
                <p class="text-sm text-slate-400">Enter Admin PIN to access the SMS Gateway Console</p>
            </div>
            
            <div class="space-y-4">
                <input type="password" id="adminPin" placeholder="Enter Admin 4-Digit PIN (Default: 7860)" class="w-full text-center py-3 bg-slate-950 border border-slate-800 rounded-xl focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-xl font-mono tracking-widest text-white outline-none">
                <button onclick="attemptAuthentication()" class="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl shadow-lg transition-all duration-200">Unlock System Dashboard</button>
                <div id="authError" class="text-xs text-rose-500 text-center font-medium hidden">⚠️ Invalid authorization PIN. Please try again.</div>
            </div>
        </div>
    </div>

    <!-- Live Console Dashboard -->
    <div id="dashboardContainer" class="max-w-7xl mx-auto px-4 py-8 space-y-8 hidden">
        <!-- Header Hub -->
        <header class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/60 backdrop-blur p-6 rounded-2xl border border-slate-800">
            <div class="flex items-center gap-4">
                <span class="text-4xl">🛰️</span>
                <div>
                    <h1 class="text-3xl font-bold tracking-tight text-white mt-1">SMS Console Hub</h1>
                    <p class="text-xs text-indigo-400 font-mono tracking-wider">SECURE TRANSMISSION SYSTEM ACTIVE</p>
                </div>
            </div>
            <button onclick="lockConsole()" class="px-5 py-2.5 bg-slate-800 hover:bg-rose-950/40 hover:text-rose-400 border border-slate-700 hover:border-rose-500/30 text-slate-300 rounded-xl text-sm font-semibold transition-all">
                Lock Console
            </button>
        </header>

        <!-- Dynamic Control Board Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            
            <!-- Column Left: Controllers -->
            <div class="space-y-8 lg:col-span-1">
                <!-- 1. Generate Terminal license key -->
                <section class="bg-slate-900/40 p-6 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-md font-bold tracking-tight text-white flex items-center gap-2"><span>🔑</span> Terminal Activation Panel</h2>
                    <p class="text-xs text-slate-400">Spawn a new cryptographic license key to register a physical Android node.</p>
                    
                    <div class="space-y-3 pt-2">
                        <input type="text" id="devLabel" placeholder="e.g., Pixel 7 Pro SIM1" class="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-300 focus:border-indigo-500 outline-none">
                        <input type="password" id="devPin" placeholder="Custom Access PIN (Optional)" class="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-300 focus:border-indigo-500 outline-none">
                        <button onclick="generateNewLicenseKey()" class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition-all shadow-md">Generate License Key</button>
                    </div>
                </section>

                <!-- 2. Global Intercept and Filter Settings -->
                <section class="bg-slate-900/40 p-6 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-md font-bold tracking-tight text-white flex items-center gap-2"><span>⚙️</span> Sync & Filter Controls</h2>
                    <p class="text-xs text-slate-400 font-medium">Filter rules are evaluated globally on incoming messages before forwarding.</p>
                    
                    <div class="space-y-3 pt-2">
                        <div>
                            <label class="text-xs text-slate-400 mb-1 block">Traffic Filter Mode</label>
                            <select id="filterMode" class="w-full px-3 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-300 outline-none">
                                <option value="ALL">Forward All Intercepts</option>
                                <option value="CONTAIN">Contains Specific Keyword</option>
                                <option value="SENDER">Sender Identity Contains</option>
                            </select>
                        </div>
                        <div>
                            <label class="text-xs text-slate-400 mb-1 block">Filtering Match Value</label>
                            <input type="text" id="targetValue" placeholder="e.g., OTP, Google, +1" class="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-300 focus:border-indigo-500 outline-none">
                        </div>
                        <button onclick="updateFilteringRules()" class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition-all">Apply Filter Rules</button>
                    </div>
                </section>

                <!-- 3. System Credentials update -->
                <section class="bg-slate-900/40 p-6 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-md font-bold tracking-tight text-white flex items-center gap-2"><span>🔒</span> Change Admin Console PIN</h2>
                    <div class="space-y-3">
                        <input type="password" id="newConsolePin" placeholder="New Admin 4-Digit PIN" class="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-300 outline-none">
                        <button onclick="updateAdminConsolePIN()" class="w-full py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded-xl text-sm transition-all border border-slate-700">Update Password PIN</button>
                    </div>
                </section>
            </div>

            <!-- Column Center & Right: Dashboard Logs & Nodes list -->
            <div class="lg:col-span-2 space-y-8">
                
                <!-- Terminal Node Status Listings -->
                <section class="bg-slate-900/40 p-6 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-md font-bold text-white flex items-center gap-2"><span>📡</span> Registered Node Terminals</h2>
                    <div class="overflow-x-auto scroller rounded-xl border border-slate-800">
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr class="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider">
                                    <th class="p-4">Terminal Device</th>
                                    <th class="p-4">Authorization Token</th>
                                    <th class="p-4">Sync PIN</th>
                                    <th class="p-4">Last Connection</th>
                                    <th class="p-4">Status</th>
                                    <th class="p-4 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="devicesList" class="divide-y divide-slate-800/60 text-sm">
                                <tr>
                                    <td colspan="6" class="p-8 text-center text-slate-500">Retrieving registered terminal data...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                <!-- Tampermonkey Integration Integration Helper -->
                <section class="bg-slate-900/40 p-6 rounded-2xl border border-slate-800 space-y-4">
                    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                        <div>
                            <h2 class="text-md font-bold text-white flex items-center gap-2"><span>🦊</span> Browser Tampermonkey Integration</h2>
                            <p class="text-xs text-slate-400 mt-0.5">Generate real-time script payloads to automatically intercept and inject OTPs inside your active browser.</p>
                        </div>
                        <select id="tamperKeySelect" onchange="updateTampermonkeyScript()" class="px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-indigo-400 outline-none">
                            <option value="">Select Associated Terminal Node</option>
                        </select>
                    </div>
                    
                    <div class="space-y-3">
                        <textarea id="tamperCode" readonly rows="6" class="w-full p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-emerald-400 outline-none resize-none scroller"></textarea>
                        <button onclick="copyTamperScript()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-xl text-xs transition-all shadow-md flex items-center gap-2">
                            Copy Integration Script Payload
                        </button>
                    </div>
                </section>

                <!-- Real-time Packet Stream Logs -->
                <section class="bg-slate-900/40 p-6 rounded-2xl border border-slate-800 space-y-4">
                    <h2 class="text-md font-bold text-white flex items-center gap-2"><span>📟</span> Intercepted Packet Stream</h2>
                    <div class="space-y-3 max-h-[500px] overflow-y-auto scroller pr-1" id="messagesStream">
                        <div class="p-8 text-center text-slate-500 bg-slate-950/30 rounded-xl">Packet stream awaiting active telemetry payloads...</div>
                    </div>
                </section>

            </div>

        </div>
    </div>

    <!-- Interface Logic Controller -->
    <script>
        let ADMIN_TOKEN = localStorage.getItem('sms_admin_pin') || '';

        document.getElementById('adminPin').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') attemptAuthentication();
        });

        async function attemptAuthentication() {
            const input = document.getElementById('adminPin').value;
            const errorText = document.getElementById('authError');
            
            try {
                const res = await fetch('/api/admin/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pin: input })
                });
                
                if (res.ok) {
                    ADMIN_TOKEN = input;
                    localStorage.setItem('sms_admin_pin', ADMIN_TOKEN);
                    errorText.classList.add('hidden');
                    document.getElementById('authContainer').classList.add('hidden');
                    document.getElementById('dashboardContainer').classList.remove('hidden');
                    bootstrapDashboardHub();
                } else {
                    errorText.classList.remove('hidden');
                }
            } catch(e) {
                alert("Authorization request server fail.");
            }
        }

        function lockConsole() {
            localStorage.removeItem('sms_admin_pin');
            ADMIN_TOKEN = '';
            location.reload();
        }

        // Initialize dashboard state if already authenticated
        if (ADMIN_TOKEN) {
            document.getElementById('authContainer').classList.add('hidden');
            document.getElementById('dashboardContainer').classList.remove('hidden');
            bootstrapDashboardHub();
        }

        function bootstrapDashboardHub() {
            fetchConsoleTelemetry();
            setInterval(fetchConsoleTelemetry, 3000);
        }

        async function fetchConsoleTelemetry() {
            try {
                const res = await fetch('/api/admin/dashboard-data', {
                    headers: { 'Authorization': ADMIN_TOKEN }
                });
                
                if (res.status === 401) {
                    lockConsole();
                    return;
                }
                
                const data = await res.json();
                if (data.success) {
                    renderTerminals(data.devices);
                    renderMessageStream(data.messages);
                    
                    // Populate drop-down
                    const tamperSelect = document.getElementById('tamperKeySelect');
                    const selectedVal = tamperSelect.value;
                    
                    const activeDevices = (data.devices || []).filter(dev => dev.status === 'Active');
                    
                    tamperSelect.innerHTML = activeDevices
                        .map(dev => \`<option value="\${dev.key}">\${dev.device_name} (\${dev.key})</option>\`)
                        .join('') || '<option value="">No Active Nodes Registered</option>';
                    
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
            
            const script = \`// ==UserScript==
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
        // Remove existing if any
        const existing = document.getElementById('sms-gateway-notification');
        if (existing) existing.remove();

        const div = document.createElement('div');
        div.id = 'sms-gateway-notification';
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
        
        window.copySmsText = function() {
            navigator.clipboard.writeText(msg.message);
            alert("SMS copied to clipboard!");
        };

        div.innerHTML = \\\`
            <div style="font-weight: bold; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
                <span>📱 SMS Received</span>
                <button onclick="document.getElementById('sms-gateway-notification').remove()" style="background: none; border: none; color: #818cf8; cursor: pointer; font-size: 16px;">×</button>
            </div>
            <div style="font-size: 11px; color: #818cf8; margin-bottom: 6px;">From: <b>\\\\\\\${msg.sender}</b></div>
            <div style="font-size: 13px; font-family: monospace; background: #090514; padding: 8px; border-radius: 6px; border: 1px solid #312e81; word-break: break-all;">
                \\\\\\\${msg.message}
            </div>
            <div style="margin-top: 8px; text-align: right;">
                <button onclick="window.copySmsText()" style="background: #4f46e5; border: none; color: white; padding: 4px 10px; border-radius: 6px; font-size: 11px; cursor: pointer; font-weight: 600;">Copy Text</button>
            </div>
        \\\`;
        document.body.appendChild(div);
        
        // Auto remove after 20 seconds
        setTimeout(() => { if (div.parentNode) div.remove(); }, 20000);
    }

    // Poll every 4 seconds
    setInterval(checkForNewMessages, 4000);
})();\`;

            document.getElementById('tamperCode').value = script;
        }

        function copyTamperScript() {
            const code = document.getElementById('tamperCode');
            code.select();
            document.execCommand('copy');
            alert("Tampermonkey Integration Script successfully copied to your clipboard!");
        }

        function renderTerminals(devices) {
            const tbody = document.getElementById('devicesList');
            if (!devices || devices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="p-8 text-center text-slate-500 bg-slate-950/20">No active device terminals generated yet.</td></tr>';
                return;
            }
            
            tbody.innerHTML = devices.map(dev => {
                const isOnline = (new Date() - new Date(dev.last_active)) < 30000; // Active within 30s
                const dateStr = dev.last_active ? new Date(dev.last_active).toLocaleTimeString() : 'Never';
                
                const statusColor = dev.status === 'Active' ? 'text-emerald-400' : 'text-rose-400';
                const pillColor = dev.status === 'Active' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400';
                
                return \`
                    <tr class="hover:bg-slate-950/40 transition-colors">
                        <td class="p-4 font-semibold text-white">
                            \${dev.device_name}
                            <span class="block text-xs font-normal text-slate-400">ID: \${dev.registered_device_id || 'Awaiting Device Sync...'}</span>
                        </td>
                        <td class="p-4 font-mono text-xs text-indigo-300">\${dev.key}</td>
                        <td class="p-4 font-mono text-xs text-slate-300 font-semibold bg-slate-950/40">\${dev.console_pin}</td>
                        <td class="p-4 text-xs text-slate-300">
                            \${dateStr}
                            \${isOnline ? '<span class="ml-1 text-[10px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded-full font-bold">LIVE</span>' : ''}
                        </td>
                        <td class="p-4 text-xs">
                            <span class="px-2 py-1 rounded-md font-semibold \${pillColor}">\${dev.status}</span>
                        </td>
                        <td class="p-4 text-right space-x-2">
                            <button onclick="toggleDeviceStatus('\${dev.key}', '\${dev.status === 'Active' ? 'Inactive' : 'Active'}')" class="text-xs font-bold text-indigo-400 hover:text-indigo-300 hover:underline">
                                \${dev.status === 'Active' ? 'Disable' : 'Enable'}
                            </button>
                            <span class="text-slate-700">|</span>
                            <button onclick="resetDeviceLock('\${dev.key}')" class="text-xs font-bold text-slate-400 hover:text-rose-400 hover:underline">
                                Unpair Hardware
                            </button>
                        </td>
                    </tr>
                \`;
            }).join('');
        }

        function renderMessageStream(messages) {
            const container = document.getElementById('messagesStream');
            if (!messages || messages.length === 0) {
                container.innerHTML = '<div class="p-8 text-center text-slate-500 bg-slate-950/30 rounded-xl">Packet stream awaiting active telemetry payloads...</div>';
                return;
            }
            
            container.innerHTML = messages.map(msg => {
                const date = new Date(msg.timestamp || msg.received_at).toLocaleTimeString();
                return \`
                    <div class="p-4 bg-slate-950/60 rounded-xl border border-indigo-950/40 hover:border-indigo-900/60 transition-all flex flex-col md:flex-row justify-between gap-4">
                        <div class="space-y-1">
                            <div class="flex items-center gap-2">
                                <span class="text-xs bg-indigo-500/10 text-indigo-300 px-2.5 py-0.5 rounded-full font-semibold font-mono">From: \${msg.sender}</span>
                                <span class="text-[11px] text-slate-400 font-mono">\${date}</span>
                                <span class="text-[11px] text-slate-500 font-mono">(\${msg.device_label || 'Default Label'} • \${msg.sim_slot})</span>
                            </div>
                            <p class="text-sm text-slate-300 font-mono select-all bg-slate-950/40 p-2 border border-slate-900 rounded-lg mt-2">\${msg.message}</p>
                        </div>
                        <div class="flex items-center justify-end">
                            <span class="text-xs px-2.5 py-0.5 bg-emerald-500/10 text-emerald-400 font-semibold rounded-md">FORWARDED</span>
                        </div>
                    </div>
                \`;
            }).join('');
        }

        async function generateNewLicenseKey() {
            const label = document.getElementById('devLabel').value;
            const customPin = document.getElementById('devPin').value;
            if (!label) {
                alert("Please provide a device label to create a key.");
                return;
            }
            
            try {
                const res = await fetch('/api/admin/generate', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ label, customPin })
                });
                const data = await res.json();
                if (data.success) {
                    alert(\`🎉 KEY CREATED!\\n\\nKey: \${data.license.key}\\nPIN: \${data.license.console_pin}\`);
                    document.getElementById('devLabel').value = '';
                    document.getElementById('devPin').value = '';
                    fetchConsoleTelemetry();
                } else {
                    alert("Error: " + data.error);
                }
            } catch(e) {
                alert("Creation request server fail.");
            }
        }

        async function toggleDeviceStatus(key, status) {
            try {
                const res = await fetch('/api/admin/status-toggle', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ key, status })
                });
                if (res.ok) fetchConsoleTelemetry();
            } catch(e) {
                alert("Failed to modify terminal status.");
            }
        }

        async function resetDeviceLock(key) {
            if (!confirm("Are you sure you want to unpair this key from its current physical hardware device?")) return;
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
                    alert("Hardware lock unpair complete. You can now use this key on any other device.");
                    fetchConsoleTelemetry();
                }
            } catch(e) {
                alert("Failed to unpair terminal.");
            }
        }

        async function updateFilteringRules() {
            const filterMode = document.getElementById('filterMode').value;
            const targetValue = document.getElementById('targetValue').value;
            
            try {
                const res = await fetch('/api/admin/rules', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': ADMIN_TOKEN
                    },
                    body: JSON.stringify({ filterMode, targetValue })
                });
                if (res.ok) alert("Global filter configurations synchronized.");
            } catch(e) {
                alert("Filters configuration failed.");
            }
        }

        async function updateAdminConsolePIN() {
            const pin = document.getElementById('newConsolePin').value;
            if (!pin || pin.length < 4) {
                alert("Please specify a valid 4-digit PIN.");
                return;
            }
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
                    alert("Global Admin Console PIN modified. System locking out to apply configuration changes.");
                    lockConsole();
                }
            } catch(e) {
                alert("Password updates failed.");
            }
        }
    </script>
</body>
</html>
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app;