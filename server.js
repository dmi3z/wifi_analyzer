// server.js
const express = require("express");
const cors = require("cors");
const { spawn, exec, execSync } = require("child_process");
const MacLookup = require("mac-lookup");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;

// MAC lookup с кешем для ускорения
async function lookupMac(bssid) {
  if (!bssid) return "unknown";

  if (macCache[bssid]) return macCache[bssid];

  try {
    // macLookup возвращает строку или null
    const vendor = await MacLookup(bssid);
    macCache[bssid] = vendor || "unknown";
    return macCache[bssid];
  } catch (err) {
    macCache[bssid] = "unknown";
    return "unknown";
  }
}

const macCache = {};

async function lookupMacCached(bssid) {
  if (!bssid) return "unknown";
  if (!macCache[bssid]) {
    macCache[bssid] = await lookupMac(bssid);
  }
  return macCache[bssid];
}

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
  const hasWPA3 = /RSN:.*Suite: SAE/.test(text) || /WPA3/.test(text); // примерный поиск WPA3
  const hasTKIP = /TKIP/.test(text);
  const hasCCMP = /CCMP/.test(text);
  const wps = /WPS:/.test(text);

  let auth = [];
  let pairwise = [];
  let group_cipher = null;
  let issues = [];
  let score = 10;

  if (hasWPA3) {
    auth.push("WPA3-SAE");
    pairwise.push("CCMP");
  }
  if (hasRSN && !hasWPA3) {
    auth.push("WPA2-PSK");
    if (hasCCMP) pairwise.push("CCMP");
    if (hasTKIP) pairwise.push("TKIP");
    if (hasTKIP) group_cipher = "TKIP";
    else group_cipher = "CCMP";
  }
  if (hasWPA) {
    auth.push("WPA-PSK");
    if (hasCCMP) pairwise.push("CCMP");
    if (hasTKIP) pairwise.push("TKIP");
    issues.push("WPA1 enabled");
    score -= 3;
    if (hasTKIP) {
      issues.push("TKIP cipher in use");
      score -= 3;
    }
  }

  // Проверка открытой сети
  const isOpen = /capability:.*Privacy/.test(text) === false;
  if (isOpen) {
    auth.push("OPEN");
    score = Math.min(score, 2); // сильно снижает безопасность
    issues.push("Open network");
  }

  // Проверка WEP (устаревший)
  const isWEP = /WEP/.test(text);
  if (isWEP) {
    auth.push("WEP");
    score = Math.min(score, 3);
    issues.push("WEP (insecure)");
  }

  // Проверка WPS
  if (wps) {
    issues.push("WPS enabled");
    score -= 2;
  }

  return {
    auth,
    pairwise_ciphers: pairwise,
    group_cipher: group_cipher || pairwise[0] || null,
    wps: !!wps,
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
  const ssid = (block.match(/SSID: (.+)/) || [])[1];
  const bssid = (block.match(/BSS ([0-9a-f:]+)/) || [])[1];
  const freq = parseInt((block.match(/freq: (\d+)/) || [])[1]);
  const signalDbm = parseFloat((block.match(/signal: (-\d+\.\d+)/) || [])[1]);
  const channel = parseInt((block.match(/channel (\d+)/) || [])[1]);
  const utilizationRaw = parseInt(
    (block.match(/channel utilisation: (\d+)/) || [])[1] || 0,
  );
  const utilization = Math.round((utilizationRaw / 255) * 100);

  const security = parseSecurity(block);
  const manufacturer = await lookupMac("c4:b8:b4:33:25:e4");

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
      manufacturer,
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

let stats = {
  totalPackets: 0,
  handshakeCount: 0,
  clients: new Set(),
};

// ==========================
// Utility functions
// ==========================
function resetStats() {
  stats = {
    totalPackets: 0,
    handshakeCount: 0,
    clients: new Set(),
  };
}

function stopTshark() {
  if (tsharkProcess) {
    console.log("Stopping old tshark...");
    tsharkProcess.kill();
    tsharkProcess = null;
  }
}

function startTshark(bssid, channel, iface) {
  console.log(`Starting capture for ${bssid} on channel ${channel}`);
  execSync(`sudo iw dev ${iface} set channel ${channel}`);
  resetStats();

  tsharkProcess = spawn("sudo", [
    "tshark",
    "-i",
    iface,
    "-Y",
    `wlan.bssid == ${bssid}`,
    "-T",
    "json",
  ]);

  tsharkProcess.stdout.on("data", (data) => {
    try {
      const packets = JSON.parse(data.toString());
      packets.forEach((pkt) => {
        stats.totalPackets++;
        if (pkt._source?.layers?.eapol) stats.handshakeCount++;
        const src = pkt._source?.layers?.["wlan.sa"];
        const dst = pkt._source?.layers?.["wlan.da"];
        if (src && src !== bssid) stats.clients.add(src);
        if (dst && dst !== bssid) stats.clients.add(dst);
      });
    } catch (e) {
      // ignore incomplete JSON chunks
    }
  });

  tsharkProcess.stderr.on("data", (d) => {
    console.error("tshark error:", d.toString());
  });

  tsharkProcess.on("close", () => {
    console.log("tshark stopped");
  });
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
// Endpoints
// ==========================

// Switch to monitor mode
app.post("/mode/monitor", (req, res) => {
  const iface = req.body.iface || "wlan2";
  try {
    stopTshark();
    execSync(`sudo ip link set ${iface} down`);
    execSync(`sudo iw dev ${iface} set type monitor`);
    execSync(`sudo ip link set ${iface} up`);
    console.log(`${iface} switched to monitor mode`);
    res.json({ status: "monitor mode enabled", iface });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to enable monitor mode" });
  }
});

app.get("/wlanconnection", (req, res) => {
  try {
    const output = execSync("iwconfig wlan0").toString();
    const interfaces = output
      .split("\n")
      .map((i) => i.trim())
      .filter((i) => i.length > 0);
    res.json(interfaces);
  } catch (err) {
    console.error("Failed to check Wi-Fi connection");
    res.status(500).json({ error: "Failed to check Wi-Fi connection" });
  }
});

// Switch back to managed mode
app.post("/mode/managed", (req, res) => {
  const iface = req.body.iface || "wlan2";
  try {
    stopTshark();
    execSync(`sudo ip link set ${iface} down`);
    execSync(`sudo iw dev ${iface} set type managed`);
    execSync(`sudo ip link set ${iface} up`);
    console.log(`${iface} switched to managed mode`);
    res.json({ status: "managed mode enabled", iface });
  } catch (err) {
    res.status(500).json({ error: "Failed to switch to managed mode" });
  }
});

// Set target BSSID and channel
app.post("/target", (req, res) => {
  const { bssid, channel, iface } = req.body;
  if (!bssid || !channel)
    return res.status(400).json({ error: "bssid and channel are required" });

  const newIface = iface || currentTarget.iface;

  currentTarget = {
    bssid: bssid.toUpperCase(),
    channel,
    iface: newIface,
  };

  ensureMonitorMode(newIface);
  stopTshark();
  startTshark(currentTarget.bssid, currentTarget.channel, currentTarget.iface);

  res.json({ status: "target set", target: currentTarget });
});

// SSE endpoint
app.get("/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  const interval = setInterval(() => {
    res.write(
      `data: ${JSON.stringify({
        ...stats,
        clients: Array.from(stats.clients),
        target: currentTarget,
      })}\n\n`,
    );
  }, 1000);

  req.on("close", () => {
    clearInterval(interval);
    console.log("Client disconnected from SSE");
  });
});

// Get list of Wi-Fi interfaces
app.get("/wlan", (req, res) => {
  try {
    const output = execSync(
      "iw dev | grep Interface | awk '{print $2}'",
    ).toString();
    const interfaces = output
      .split("\n")
      .map((i) => i.trim())
      .filter((i) => i.length > 0);
    res.json(interfaces);
  } catch (err) {
    console.error("Failed to get Wi-Fi interfaces");
    res.status(500).json({ error: "Failed to get Wi-Fi interfaces" });
  }
});

// ==========================
// Wi-Fi scan endpoint (original version, unchanged)
// ==========================
app.get("/wifi", async (req, res) => {
  exec("sudo iw dev wlan1 scan", async (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });

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

    res.json(results);
  });
});

// ==========================
// Start server
// ==========================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Wi-Fi analyzer server running on http://localhost:${PORT}`);
});
