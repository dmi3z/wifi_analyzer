// WiFi module for wifi_analyzer
const { exec, execSync, spawn } = require("child_process");

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
let currentTarget = null;
let tsharkProcess = null;
let packetStats = {
  totalPackets: 0,
  targetPackets: 0,
  pps: 0
};

// Calculate PPS every second globally
setInterval(() => {
  packetStats.pps = packetStats.totalPackets;
  packetStats.totalPackets = 0;
}, 1000);

// --- Start tshark process with BSSID filter ---
function startTsharkWithFilter(targetBSSID) {
  console.log(`[DEBUG] startTsharkWithFilter called with BSSID: ${targetBSSID}`);
  console.log(`[DEBUG] Current tsharkProcess exists: ${!!tsharkProcess}`);
  console.log(`[DEBUG] Starting tshark with filter for BSSID: ${targetBSSID}`);
  
  const tsharkArgs = [
    "tshark",
    "-i", "wlan2",
    "-Y", `wlan.bssid == ${targetBSSID}`,
    "-T", "fields",
    "-e", "frame.time_epoch"
  ];
  
  tsharkProcess = spawn("sudo", tsharkArgs);

  tsharkProcess.stdout.on("data", (data) => {
    const lines = data.toString().split('\n');
    
    for (const line of lines) {
      if (!line.trim()) continue;
      
      packetStats.totalPackets++;
      packetStats.targetPackets++;
    }
  });

  tsharkProcess.stderr.on("data", (data) => {
    console.log(`[DEBUG] tshark stderr: ${data.toString().trim()}`);
  });

  tsharkProcess.on("close", (code) => {
    console.log(`[DEBUG] tshark process stopped with code: ${code}`);
    tsharkProcess = null;
  });

  tsharkProcess.on("error", (err) => {
    console.log(`[DEBUG] tshark process error: ${err.message}`);
  });

  console.log(`[DEBUG] tshark started with filter for ${targetBSSID}, function returning`);
}

// ==========================
// Utility functions
// ==========================

// Set target BSSID for filtering
function setTarget(bssid, channel, iface) {
  console.log(`[DEBUG] setTarget called with bssid=${bssid}, channel=${channel}, iface=${iface}`);
  
  currentTarget = {
    bssid: bssid.toLowerCase(),
    channel: channel,
    iface: iface
  };
  
  console.log(`[DEBUG] currentTarget set to: ${JSON.stringify(currentTarget)}`);
  
  // Start tshark asynchronously to avoid blocking
  console.log(`[DEBUG] About to call startTsharkWithFilter asynchronously`);
  startTsharkWithFilter(bssid);

  
  console.log(`[DEBUG] setTarget completed, returning response immediately`);
  return { status: "target set", target: currentTarget };
}

// Get current stats for SSE
// function getStats() {
//   return {
//     pps: packetStats.pps,
//     targetPackets: packetStats.targetPackets,
//     currentTarget: currentTarget,
//     timestamp: new Date().toISOString()
//   };
// }

// Stop capture (cleanup)
function stopCapture() {
  if (tsharkProcess) {
    console.log("Stopping tshark process...");
    tsharkProcess.kill("SIGTERM");
    tsharkProcess = null;
  }
  currentTarget = null;
  console.log("Capture stopped");
}

// Simple functions for compatibility
function switchToMonitorMode(iface = "wlan2") {
  return { status: "monitor mode already set", iface };
}

function switchToManagedMode(iface = "wlan2") {
  return { status: "managed mode", iface };
}

function startTshark(bssid, channel, iface) {
  return setTarget(bssid, channel, iface);
}

function stopTshark() {
  return stopCapture();
}

function saveHandshakes() {
  return { success: false, message: "Handshake saving not implemented in simple mode" };
}

function isValidMAC(mac) {
  if (!mac) return false;
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
    try {
      execSync(`sudo ip link set ${iface} down`, { stdio: "ignore" });
      execSync(`sudo iw dev ${iface} del`, { stdio: "ignore" });
    } catch (delError) {
      // Interface may not exist, ignore error
    }

    // Create separate monitor interface
    execSync(`sudo iw dev ${iface} interface add ${iface} type monitor`);
    execSync(`sudo ip link set ${iface} up`);

    console.log(`${monIface} monitor interface created from ${iface}`);
    return { status: "monitor mode enabled", iface };
  } catch (err) {
    console.error(err);
    throw new Error("Failed to enable monitor mode");
  }
}

// Switch back to managed mode
function switchToManagedMode(iface = "wlan2") {
  try {
    stopTshark(); // This will clean up wlan2mon interface

    // Original interface (wlan2) should already be in managed mode
    // since we never changed it - we only created wlan2mon
    console.log(
      `${iface} already in managed mode (monitor interface cleaned up)`,
    );
    return { status: "managed mode restored", iface };
  } catch (err) {
    throw new Error("Failed to restore managed mode");
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
  stopTshark,
  startTshark,
  ensureMonitorMode,

  // Global data
  currentTarget,
  packetStats,
  tsharkProcess,

  // Accessors for global data
  getCurrentTarget: () => currentTarget,
  getStats: () => packetStats,
};
