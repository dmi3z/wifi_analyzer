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
  const hasWPA3 = /RSN:.*Suite: SAE/.test(text) || /WPA3/.test(text); // примерный поиск WPA3
  const hasTKIP = /TKIP/.test(text);
  const hasCCMP = /CCMP/.test(text);
  const wpsRegex = /IE: .*Vendor Specific.*WFA.*WPS/i;
  const wps = wpsRegex.test(text);

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

  if (
    auth.includes("WPA2-PSK") &&
    !text.includes("SAE") &&
    !text.includes("WPA3")
  ) {
    issues.push("Deauth vulnerable");
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

let stats = {
  totalPackets: 0,
  handshakeCount: 0,
  clients: new Set(),
  lastSeen: new Map(), // Время последнего обнаружения для каждого клиента
};

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
}

function startTshark(bssid, channel, iface) {
  console.log(`Starting capture for ${bssid} on channel ${channel}`);
  execSync(`sudo iw dev ${iface} set channel ${channel}`);
  resetStats();

  const { spawn } = require("child_process");
  tsharkProcess = spawn("sudo", [
    "tshark",
    "-i",
    iface,
    "-Y",
    `wlan.bssid == ${bssid} || wlan.da == ${bssid} || wlan.sa == ${bssid}`,
    "-T",
    "fields",
    "-e",
    "wlan.sa",
    "-e",
    "wlan.da",
    "-e",
    "wlan.bssid",
    "-e",
    "wlan.fc.type_subtype",
    "-e",
    "eapol",
  ]);

  console.log(`tshark started with PID: ${tsharkProcess.pid}`);

  // Интервал для удаления "мертвых" клиентов (мс)
  const CLIENT_TIMEOUT = 30000; // 30 секунд

  tsharkProcess.stdout.on("data", (data) => {
    try {
      const lines = data.toString().trim().split("\n");
      const now = Date.now();

      lines.forEach((line) => {
        if (!line.trim()) return;

        const [src, dst, bssid, packetTypeRaw, eapol] = line.split("\t");
        if (!src || !dst || !bssid) return;

        // Проверяем что все поля определены
        if (!src || !dst || !bssid || !packetTypeRaw) return;

        const bssidLower = bssid.toLowerCase();
        // Фильтруем только пакеты от/к целевой сети
        if (bssidLower !== bssid.toLowerCase()) return;

        const srcLower = src.toLowerCase();
        const dstLower = dst.toLowerCase();
        const packetType = packetTypeRaw.toLowerCase().replace("0x", "");

        stats.totalPackets++;
        if (stats.totalPackets <= 20 || stats.totalPackets % 100 === 0) {
          console.log(
            `Packet ${stats.totalPackets}: src=${src}, dst=${dst}, bssid=${bssid}, type=${packetType}, eapol=${eapol}`,
          );
        }

        // -------------------------------
        // 1️⃣ Добавляем handshake / EAPOL как клиента
        // -------------------------------
        if (eapol && eapol !== "") {
          stats.handshakeCount++;
          [srcLower, dstLower].forEach((mac) => {
            if (mac !== bssidLower && isValidMAC(mac)) {
              stats.clients.add(mac);
              stats.lastSeen.set(mac, now);
            }
          });
          console.log(`Handshake detected! Total: ${stats.handshakeCount}`);
        }

        // -------------------------------
        // 2️⃣ Для клиентов - игнорируем broadcast/multicast
        // -------------------------------
        if (!isValidMAC(srcLower) || !isValidMAC(dstLower)) return;

        // -------------------------------
        // 3️⃣ Клиент → AP (строгая фильтрация)
        // -------------------------------
        if (srcLower !== bssidLower && dstLower === bssidLower) {
          if (["20", "08"].includes(packetType)) {
            // Только Data и QoS Data
            if (
              isValidMAC(srcLower) &&
              !srcLower.startsWith("02:") &&
              !srcLower.startsWith("00:")
            ) {
              stats.clients.add(srcLower);
              stats.lastSeen.set(srcLower, now);
              console.log(
                `Client detected: ${srcLower} (to AP, type: ${packetType})`,
              );
            }
          }
        }
        // -------------------------------
        // 4️⃣ AP → Клиент (строгая фильтрация)
        // -------------------------------
        else if (srcLower === bssidLower && dstLower !== bssidLower) {
          if (["20", "08"].includes(packetType)) {
            // Только Data и QoS Data
            if (
              isValidMAC(dstLower) &&
              !dstLower.startsWith("02:") &&
              !dstLower.startsWith("00:")
            ) {
              stats.clients.add(dstLower);
              stats.lastSeen.set(dstLower, now);
              console.log(
                `Client detected: ${dstLower} (from AP, type: ${packetType})`,
              );
            }
          }
        }

        // -------------------------------
        // 5️⃣ Удаляем "мертвые" клиенты
        // -------------------------------
        for (const [mac, ts] of stats.lastSeen.entries()) {
          if (now - ts > CLIENT_TIMEOUT) {
            stats.clients.delete(mac);
            stats.lastSeen.delete(mac);
          }
        }
      });
    } catch (e) {
      console.error("Parse error:", e.message);
    }
  });

  tsharkProcess.stderr.on("data", (d) => {
    console.error("tshark error:", d.toString());
  });

  tsharkProcess.on("close", (code) => {
    console.log(`tshark stopped with code: ${code}`);
  });

  tsharkProcess.on("error", (err) => {
    console.error("tshark process error:", err);
  });
}

function stopTshark() {
  console.log("Stopping all tshark processes...");

  // Убиваем все tshark процессы
  exec("sudo killall tshark", (error, stdout, stderr) => {
    if (error) {
      console.log(
        "No tshark processes to kill or killall failed:",
        error.message,
      );
    } else {
      console.log("All tshark processes killed");
    }
  });

  // Также пробуем убить конкретный процесс если он есть
  if (tsharkProcess) {
    const pid = tsharkProcess.pid;
    exec(`sudo kill -TERM ${pid}`, (error) => {
      setTimeout(() => {
        exec(`sudo kill -KILL ${pid}`, (killError) => {
          console.log(`tshark process ${pid} kill attempt completed`);
        });
      }, 1000);
    });
    tsharkProcess = null;
  }

  resetStats();
  console.log("tshark stopped and stats reset");
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

  // Global data
  currentTarget,
  stats,
  tsharkProcess,

  // Accessors for global data
  getCurrentTarget: () => currentTarget,
  getStats: () => stats,
};
