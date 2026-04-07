// WiFi module for wifi_analyzer
const { exec, execSync } = require("child_process");

// --- Вспомогательные функции ---
function signalQuality(dbm) {
  if (dbm >= -60) return "excellent";
  if (dbm >= -70) return "good";
  if (dbm >= -80) return "fair";
  return "poor";
}

function getBand(freq) {
  return freq < 3000 ? "2.4GHz" : "5GHz";
}

function getOverlappingChannels(channel) {
  const overlaps = [];
  for (let i = channel - 4; i <= channel + 4; i++) {
    if (i >= 1 && i <= 13 && i !== channel) overlaps.push(i);
  }
  return overlaps;
}

function parseSecurity(text) {
  const hasWPA = /WPA:\s+\* Version: 1/.test(text);
  const hasRSN = /RSN:/.test(text);
  const hasWPA3 = /RSN:.*Suite: SAE/.test(text) || /WPA3/.test(text);
  const hasTKIP = /TKIP/.test(text);
  const hasCCMP = /CCMP/.test(text);
  const wpsRegex = /IE: .*Vendor Specific.*WFA.*WPS/i;
  const wps = wpsRegex.test(text);

  let auth = [];
  let pairwise = [];
  let group_cipher = null;
  let issues = [];

  let score = 10; // максимальный

  if (hasWPA3) {
    auth.push("WPA3-SAE");
    pairwise.push("CCMP");
  }

  if (hasRSN && !hasWPA3) {
    auth.push("WPA2-PSK");
    if (hasCCMP) pairwise.push("CCMP");
    if (hasTKIP) pairwise.push("TKIP");
    group_cipher = hasTKIP ? "TKIP" : "CCMP";
  }

  if (hasWPA) {
    auth.push("WPA-PSK");
    if (hasCCMP) pairwise.push("CCMP");
    if (hasTKIP) pairwise.push("TKIP");
    issues.push("WPA1 enabled");
    score -= 3;
    if (hasTKIP) {
      issues.push("TKIP cipher in use");
      score -= 2;
    }
  }

  // Уязвимость к деаутентификации (если WPA2 без SAE)
  if (auth.includes("WPA2-PSK") && !hasWPA3) {
    issues.push("Deauth vulnerable");
    score -= 1;
  }

  // Открытая сеть
  const isOpen = /capability:.*Privacy/.test(text) === false;
  if (isOpen) {
    auth.push("OPEN");
    score = Math.min(score, 2); // минимум безопасности
    issues.push("Open network");
  }

  // WEP
  const isWEP = /WEP/.test(text);
  if (isWEP) {
    auth.push("WEP");
    score = Math.min(score, 3);
    issues.push("WEP (insecure)");
  }

  // WPS
  if (wps) {
    issues.push("WPS enabled");
    score = Math.max(score - 2, 1); // никогда не уходит ниже 1
  }

  // Ограничиваем score от 1 до 10
  score = Math.max(Math.min(score, 10), 1);

  return {
    auth,
    pairwise_ciphers: pairwise,
    group_cipher: group_cipher || pairwise[0] || null,
    wps,
    security_level: score >= 7 ? "good" : score >= 5 ? "medium" : "weak",
    score,
    issues,
  };
}

function computeOverall({
  signalDbm,
  securityScore,
  utilization,
  interferenceScore,
}) {
  const signalScore =
    signalDbm >= -60 ? 10 : signalDbm >= -70 ? 8 : signalDbm >= -80 ? 6 : 3;

  const loadScore = utilization < 30 ? 10 : utilization < 70 ? 7 : 4;

  return (
    signalScore * 0.3 +
    securityScore * 0.4 +
    loadScore * 0.2 +
    interferenceScore * 0.1
  ).toFixed(1);
}

async function parseNetworkBlock(block, allChannels) {
  const ssid = (block.match(/SSID: (.+)/) || [])[1] || null;
  const bssid = (block.match(/BSS ([0-9a-f:]+)/) || [])[1];
  const freq = parseInt((block.match(/freq: (\d+)/) || [])[1]);
  const signalDbm = parseFloat((block.match(/signal: (-\d+\.\d+)/) || [])[1]);
  const channel = parseInt((block.match(/channel (\d+)/) || [])[1]);
  const utilizationRaw = parseInt(
    (block.match(/channel utilisation: (\d+)/) || [])[1] || 0,
  );
  const utilization = Math.round((utilizationRaw / 255) * 100);

  const security = parseSecurity(block);

  // Interference
  const overlappingChannels = getOverlappingChannels(channel);
  const overlappingNetworks = allChannels.filter((n) =>
    overlappingChannels.includes(n.channel),
  ).length;
  const interferenceLevel =
    overlappingNetworks === 0
      ? "low"
      : overlappingNetworks < 3
        ? "medium"
        : "high";
  const interferenceScore =
    interferenceLevel === "low" ? 10 : interferenceLevel === "medium" ? 6 : 3;

  const overallScore = computeOverall({
    signalDbm,
    securityScore: security.score,
    utilization,
    interferenceScore,
  });

  return {
    identity: {
      ssid,
      bssid,
      manufacturer: "unknown", // Will be set by caller if needed
    },
    radio: {
      band: getBand(freq),
      frequency_mhz: freq,
      channel,
      signal_dbm: signalDbm,
      signal_quality: signalQuality(signalDbm),
    },
    security,
    load: {
      channel_utilization_percent: utilization,
    },
    interference: {
      overlapping_networks: overlappingNetworks,
      interference_level: interferenceLevel,
    },
    overall_score: Number(overallScore),
  };
}

// ==========================
// Global variables
// ==========================
let currentTarget = {
  bssid: null,
  channel: null,
  iface: "wlan2",
};

let tsharkProcess = null;
let hcxdumptoolProcess = null; // Main process for all data collection

let stats = {
  totalPackets: 0,
  handshakeCount: 0,
  clients: new Set(),
  lastSeen: new Map(), // Время последнего обнаружения для каждого клиента
};

let capturedHandshakes = []; // Store captured handshake data with timestamps and packet info

// Очистка неактивных клиентов каждые 30 секунд
setInterval(() => {
  const now = Date.now();
  const timeout = 10000; // 10 секунд неактивности

  for (const [mac, lastSeen] of stats.lastSeen.entries()) {
    if (now - lastSeen > timeout) {
      stats.clients.delete(mac);
      stats.lastSeen.delete(mac);
      console.log(`Removed inactive client: ${mac}`);
    }
  }
}, 30000);

// ==========================
// Utility functions
// ==========================
function resetStats() {
  stats = {
    totalPackets: 0,
    handshakeCount: 0,
    clients: new Set(),
    lastSeen: new Map(),
  };
  capturedHandshakes = [];
}

function startTshark(bssid, channel, iface) {
  console.log(`Starting capture for ${bssid} on channel ${channel} using hcxdumptool`);
  
  try {
    // Stop any existing processes
    try {
      execSync(`sudo killall hcxdumptool`, { stdio: 'ignore' });
    } catch (killError) {
      // Ignore "no process found" errors - this is normal
      if (!killError.message.includes('no process found') && !killError.message.includes('not found')) {
        console.log('Warning: killall hcxdumptool failed:', killError.message);
      }
    }
    
    // Only set monitor mode if not already set (avoid conflicts with /mode/monitor)
    try {
      const modeCheck = execSync(`sudo iw dev ${iface} info | grep "type monitor"`, { stdio: 'pipe' }).toString();
      if (!modeCheck.includes('monitor')) {
        console.log('Monitor mode not detected, setting it up...');
        execSync(`sudo ip link set ${iface} down`);
        execSync(`sudo iw dev ${iface} set type monitor`);
        execSync(`sudo ip link set ${iface} up`);
      } else {
        console.log('Monitor mode already enabled');
      }
    } catch (modeError) {
      console.log('Checking monitor mode failed, setting it up anyway...');
      execSync(`sudo ip link set ${iface} down`);
      execSync(`sudo iw dev ${iface} set type monitor`);
      execSync(`sudo ip link set ${iface} up`);
    }
    
    // Set channel
    execSync(`sudo iw dev ${iface} set channel ${channel}`);
    
    // Verify final interface state
    const finalModeCheck = execSync(`sudo iw dev ${iface} info | grep type`).toString();
    console.log(`Final interface mode: ${finalModeCheck.trim()}`);
    
    resetStats();

    const { spawn } = require("child_process");
    
    // Use hcxdumptool for all data collection
    hcxdumptoolProcess = spawn("sudo", [
      "hcxdumptool",
      "-i", iface,
      "-c", channel.toString(),
      "--rds", "2",
      "--exitoneapol", "15"
    ]);

    hcxdumptoolProcess.stdout.on("data", (data) => {
      const output = data.toString();
      const lines = output.split('\n');
      
      for (const line of lines) {
        if (!line.trim()) continue;
        
        // Log all output for debugging
        console.log(`hcxdumptool: ${line.trim()}`);
        
        // Parse different types of output from hcxdumptool
        if (line.includes('HANDSHAKE') || line.includes('PMKID') || line.includes('EAPOL')) {
          stats.handshakeCount++;
          
          // Store handshake data
          const handshakeData = {
            timestamp: new Date().toISOString(),
            bssid: bssid,
            channel: channel,
            iface: iface,
            type: line.includes('PMKID') ? 'PMKID' : (line.includes('HANDSHAKE') ? 'HANDSHAKE' : 'EAPOL'),
            rawOutput: line.trim(),
            source: 'hcxdumptool',
            target: currentTarget
          };
          capturedHandshakes.push(handshakeData);
        }
        
        // Extract any MAC addresses as potential clients
        const macMatches = line.match(/([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})/gi);
        if (macMatches) {
          macMatches.forEach(mac => {
            const clientMac = mac.toLowerCase();
            if (clientMac !== bssid.toLowerCase() && isValidMAC(clientMac)) {
              stats.clients.add(clientMac);
              stats.lastSeen.set(clientMac, Date.now());
            }
          });
        }
        
        // Count packets - any line with activity indicates packets
        if (line.includes(bssid.toLowerCase()) || line.includes('packet') || line.includes('frame') || line.includes('received')) {
          stats.totalPackets++;
        }
        
        // Fallback: increment packet count for any meaningful output
        if (stats.totalPackets < 1000 && line.trim().length > 10) {
          stats.totalPackets++;
        }
      }
    });

    hcxdumptoolProcess.stderr.on("data", (data) => {
      console.error("hcxdumptool error:", data.toString());
    });

    hcxdumptoolProcess.on("close", (code) => {
      console.log(`hcxdumptool stopped with code: ${code}`);
    });

    hcxdumptoolProcess.on("error", (err) => {
      console.error("hcxdumptool process error:", err);
    });

    return { status: "capture started", target: { bssid, channel, iface } };
    
  } catch (error) {
    console.error("Failed to start hcxdumptool:", error.message);
    throw new Error(`Failed to start capture: ${error.message}`);
  }
}

function stopTshark() {
  console.log("Stopping hcxdumptool process...");

  // Kill hcxdumptool processes
  exec("sudo killall hcxdumptool", (error, stdout, stderr) => {
    if (error) {
      console.log(
        "killall hcxdumptool failed (process may not be running):",
        error.message,
      );
    } else {
      console.log("Successfully killed hcxdumptool processes");
    }
  });

  // Kill tracked process if it exists
  if (hcxdumptoolProcess) {
    hcxdumptoolProcess.kill("SIGTERM");
    hcxdumptoolProcess = null;
  }

  resetStats();
  console.log("hcxdumptool stopped and stats reset");
}

// Вспомогательная функция для проверки MAC
function isValidMAC(mac) {
  if (!mac) return false;
  mac = mac.toLowerCase();
  if (mac === "ff:ff:ff:ff:ff:ff") return false;
  if (mac.startsWith("33:33") || mac.startsWith("01:00:5e")) return false;
  return true;
}

function ensureMonitorMode(iface) {
  try {
    const output = execSync(`iw dev ${iface} info`).toString();
    if (!output.includes("type monitor")) {
      execSync(`sudo ip link set ${iface} down`);
      execSync(`sudo iw dev ${iface} set type monitor`);
      execSync(`sudo ip link set ${iface} up`);
      console.log(`${iface} switched to monitor mode`);
    }
  } catch (e) {
    console.error("Failed to check/set monitor mode");
  }
}

// ==========================
// WiFi Functions
// ==========================

// Switch to monitor mode
function switchToMonitorMode(iface = "wlan2") {
  try {
    execSync(`sudo ip link set ${iface} down`);
    execSync(`sudo iw dev ${iface} set type monitor`);
    execSync(`sudo ip link set ${iface} up`);
    console.log(`${iface} switched to monitor mode`);
    return { status: "monitor mode enabled", iface };
  } catch (err) {
    console.error(err);
    throw new Error("Failed to enable monitor mode");
  }
}

// Switch back to managed mode
function switchToManagedMode(iface = "wlan2") {
  try {
    stopTshark();
    execSync(`sudo ip link set ${iface} down`);
    execSync(`sudo iw dev ${iface} set type managed`);
    execSync(`sudo ip link set ${iface} up`);
    console.log(`${iface} switched to managed mode`);
    return { status: "managed mode enabled", iface };
  } catch (err) {
    throw new Error("Failed to switch to managed mode");
  }
}

// Get WLAN connection info
function getWlanConnection() {
  try {
    const output = execSync("iwconfig wlan0").toString();
    const interfaces = output
      .split("\n")
      .map((i) => i.trim())
      .filter((i) => i.length > 0);
    return interfaces;
  } catch (err) {
    console.error("Failed to check Wi-Fi connection");
    throw new Error("Failed to check Wi-Fi connection");
  }
}

// Get list of Wi-Fi interfaces
function getWlanInterfaces() {
  try {
    const output = execSync(
      "iw dev | grep Interface | awk '{print $2}'",
    ).toString();
    const interfaces = output
      .split("\n")
      .map((i) => i.trim())
      .filter((i) => i.length > 0);
    return interfaces;
  } catch (err) {
    console.error("Failed to get Wi-Fi interfaces");
    throw new Error("Failed to get Wi-Fi interfaces");
  }
}

// Save captured handshakes to file
function saveHandshakes() {
  const fs = require('fs');
  const path = require('path');
  
  if (capturedHandshakes.length === 0 && stats.handshakeCount === 0) {
    return { success: false, message: "No handshakes captured" };
  }
  
  // Create filename with timestamp and target BSSID
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const bssid = currentTarget ? currentTarget.bssid.replace(/:/g, '-') : 'unknown';
  const filename = `handshakes_${bssid}_${timestamp}.json`;
  const filepath = path.join(process.cwd(), 'captured_handshakes', filename);
  
  // Ensure directory exists
  const dir = path.dirname(filepath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  // Prepare handshake data - combine capturedHandshakes with basic handshake info if needed
  let handshakesToSave = [...capturedHandshakes];
  
  // If we have handshakeCount but no detailed data, create basic entries
  if (capturedHandshakes.length === 0 && stats.handshakeCount > 0) {
    handshakesToSave = [{
      timestamp: new Date().toISOString(),
      bssid: currentTarget ? currentTarget.bssid : 'unknown',
      channel: currentTarget ? currentTarget.channel : null,
      iface: currentTarget ? currentTarget.iface : null,
      type: 'EAPOL',
      source: 'tshark',
      note: `Detected by tshark - ${stats.handshakeCount} total handshakes`,
      target: currentTarget
    }];
  }
  
  // Save handshakes with metadata
  const data = {
    metadata: {
      timestamp: new Date().toISOString(),
      target: currentTarget,
      totalHandshakes: stats.handshakeCount,
      totalPackets: stats.totalPackets,
      detailedHandshakes: capturedHandshakes.length,
      clients: Array.from(stats.clients)
    },
    handshakes: handshakesToSave
  };
  
  try {
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
    return { 
      success: true, 
      message: `Saved ${stats.handshakeCount} handshakes to ${filename}`,
      filename: filename,
      filepath: filepath,
      count: stats.handshakeCount,
      detailedCount: capturedHandshakes.length
    };
  } catch (error) {
    return { success: false, message: `Error saving handshakes: ${error.message}` };
  }
}

// Set target BSSID and channel
function setTarget(bssid, channel, iface) {
  if (!bssid || !channel) {
    throw new Error("bssid and channel are required");
  }

  const newIface = iface || currentTarget.iface;

  currentTarget = {
    bssid: bssid.toUpperCase(),
    channel,
    iface: newIface,
  };

  ensureMonitorMode(newIface);
  stopTshark();
  startTshark(currentTarget.bssid, currentTarget.channel, currentTarget.iface);

  return { status: "target set", target: currentTarget };
}

// Wi-Fi scan endpoint
async function scanWifi() {
  return new Promise((resolve, reject) => {
    exec("sudo iw dev wlan1 scan", async (err, stdout) => {
      if (err) return reject(new Error(err.message));

      const networkBlocks = stdout
        .split(/\nBSS /)
        .map((b, i) => (i === 0 ? b : "BSS " + b));
      const allChannels = networkBlocks.map((b) => ({
        channel: parseInt((b.match(/channel (\d+)/) || [])[1]),
      }));

      const results = [];
      for (const block of networkBlocks) {
        const info = await parseNetworkBlock(block, allChannels);
        results.push(info);
      }

      resolve(results);
    });
  });
}

// Export functions and data
module.exports = {
  // Utility functions
  signalQuality,
  getBand,
  getOverlappingChannels,
  parseSecurity,
  computeOverall,
  parseNetworkBlock,

  // WiFi management
  switchToMonitorMode,
  switchToManagedMode,
  getWlanConnection,
  getWlanInterfaces,
  setTarget,
  scanWifi,

  // Stats and monitoring
  resetStats,
  stopTshark,
  startTshark,
  ensureMonitorMode,
  saveHandshakes,

  // Global data
  currentTarget,
  stats,
  tsharkProcess,
  capturedHandshakes,

  // Accessors for global data
  getCurrentTarget: () => currentTarget,
  getStats: () => stats,
};
