// server.js
const express = require("express");
const cors = require("cors");
const { spawn, exec, execSync } = require("child_process");
const noble = require("@abandonware/noble");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;

const ouiText = fs.readFileSync("oui.txt", "utf8");
const ouiMap = {};
let devices = {};
let history = [];
let clients = [];

ouiText.split("\n").forEach((line) => {
  const m = line.match(
    /^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)/i,
  );
  if (m) ouiMap[m[1].toLowerCase().replace(/-/g, ":")] = m[2].trim();
});

function lookupMacLocal(bssid) {
  const prefix = bssid.toLowerCase().split(":").slice(0, 3).join(":");
  return ouiMap[prefix] || "unknown";
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
  const manufacturer = lookupMacLocal(bssid);

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

//// BLE functions

function parseManufacturerData(buf) {
  if (!buf) return null;

  const hex = buf.toString("hex");

  // Apple (iBeacon)
  if (hex.startsWith("4c00")) {
    return parseIBeacon(buf);
  }

  // Google (Eddystone)
  if (hex.startsWith("aa")) {
    return parseEddystone(buf);
  }

  return {
    raw: hex,
  };
}

function parseIBeacon(buf) {
  // iBeacon format:
  // 4c00 02 15 UUID(16) major(2) minor(2) txPower(1)

  if (buf.length < 25) return null;

  const uuid = buf.slice(4, 20).toString("hex");
  const major = buf.readUInt16BE(20);
  const minor = buf.readUInt16BE(22);
  const txPower = buf.readInt8(24);

  return {
    type: "ibeacon",
    uuid,
    major,
    minor,
    txPower,
  };
}

function parseEddystone(buf) {
  const frameType = buf[2];

  if (frameType === 0x00) {
    // UID
    return {
      type: "eddystone_uid",
    };
  }

  if (frameType === 0x10) {
    // URL
    return {
      type: "eddystone_url",
    };
  }

  return {
    type: "eddystone_unknown",
  };
}

function detectDevice(p) {
  const name = p.advertisement.localName || "";
  const mfg = p.advertisement.manufacturerData;

  if (name.includes("AirPods")) {
    return { type: "audio", vendor: "Apple" };
  }

  if (mfg) {
    const hex = mfg.toString("hex");

    if (hex.startsWith("4c00")) {
      return { type: "apple_device", vendor: "Apple" };
    }

    if (hex.startsWith("6f")) {
      return { type: "xiaomi", vendor: "Xiaomi" };
    }
  }

  return { type: "unknown", vendor: "unknown" };
}

// ==========================
// Endpoints
// ==========================

/////=== Bluetooth

app.get("/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  clients.push(res);

  req.on("close", () => {
    clients = clients.filter((c) => c !== res);
  });
});

function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  clients.forEach((c) => c.write(payload));
}

// --- BLE SCAN ---
app.post("/bluetooth/off", (req, res) => {
  exec("sudo rfkill block bluetooth", () => res.json({ status: "off" }));
});

app.post("/bluetooth/on", (req, res) => {
  exec("sudo rfkill unblock bluetooth", () => res.json({ status: "on" }));
});

noble.on("stateChange", (state) => {
  if (state === "poweredOn") noble.startScanning([], true);
  else noble.stopScanning();
});

noble.on("discover", (p) => {
  const mac = p.address || "unknown";
  const name = p.advertisement.localName || "unknown";
  const rssi = p.rssi;
  const now = Date.now();

  const mfgParsed = parseManufacturerData(p.advertisement.manufacturerData);
  const detected = detectDevice(p);

  if (!devices[mac]) {
    devices[mac] = {
      mac,
      name,
      rssi,
      first_seen: now,
    };
  }

  devices[mac] = {
    ...devices[mac],
    name,
    rssi,
    last_seen: now,
    manufacturer: mfgParsed,
    ...detected,
  };

  history.push({
    mac,
    rssi,
    ts: now,
  });

  if (history.length > 1000) history.shift();

  broadcast("device", devices[mac]);
});

// --- API ---

// список текущих устройств
app.get("/devices", (req, res) => {
  res.json(Object.values(devices));
});

// конкретное устройство
app.get("/devices/:mac", (req, res) => {
  res.json(devices[req.params.mac] || {});
});

// топ по RSSI
app.get("/devices/top/:n", (req, res) => {
  const n = parseInt(req.params.n);
  const sorted = Object.values(devices)
    .sort((a, b) => b.rssi - a.rssi)
    .slice(0, n);
  res.json(sorted);
});

// история (из RAM)
app.get("/history", (req, res) => {
  res.json(history.slice(-100)); // последние 100
});

// очистка
app.delete("/devices", (req, res) => {
  devices = {};
  history = [];
  res.json({ ok: true });
});

// Подключение к Bluetooth устройству по MAC адресу
app.post("/bluetooth/connect/:mac", async (req, res) => {
  const mac = req.params.mac.toLowerCase();
  
  try {
    // Найти устройство среди обнаруженных
    const device = Object.values(devices).find(d => d.mac.toLowerCase() === mac);
    
    if (!device) {
      return res.status(404).json({ 
        error: "Device not found", 
        message: "Device not found" 
      });
    }

    // Попытка найти и подключиться к peripheral
    // Сначала проверяем в _peripherals
    let peripheral = noble._peripherals[mac];
    
    if (!peripheral) {
      // Если не нашли, попробуем найти через startScanning и ждать discovery
      console.log(`Device ${mac} not in _peripherals, starting scan...`);
      console.log('Available peripherals:', Object.keys(noble._peripherals));
      
      const timeout = setTimeout(() => {
        noble.stopScanning();
        noble.removeListener('discover', onDiscover);
        console.log(`Scan timeout for ${mac}`);
        return res.status(404).json({ 
          error: "Device not found after scanning", 
          message: `Device ${mac} not found after 10 seconds of scanning` 
        });
      }, 10000);

      const onDiscover = (peripheral) => {
        console.log(`Discovered device: ${peripheral.address} (looking for ${mac})`);
        if (peripheral.address.toLowerCase() === mac) {
          clearTimeout(timeout);
          noble.removeListener('discover', onDiscover);
          noble.stopScanning();
          
          console.log(`Found target device ${mac}, attempting connection...`);
          peripheral.connect((error) => {
            if (error) {
              console.error(`Connection error for ${mac}:`, error);
              return res.status(500).json({ 
                error: "Connection failed", 
                message: `Connection failed to ${mac}: ${error.message}` 
              });
            } else {
              console.log(`Successfully connected to ${mac}`);
              
              // Попытка найти сервисы и отправить команду уменьшения громкости
              peripheral.discoverServices([], (error, services) => {
                if (error) {
                  console.error('Service discovery error:', error);
                  return res.json({ 
                    status: "connected", 
                    mac: mac,
                    device: device,
                    message: `Successfully connected to ${mac} (service discovery failed)` 
                  });
                }

                console.log(`Found ${services.length} services for ${mac}`);
                
                // Ищем сервисы, связанные с аудио
                const audioServices = services.filter(service => {
                  const uuid = service.uuid.toLowerCase();
                  return uuid.includes('audio') || uuid.includes('volume') || 
                         uuid.includes('180b') || uuid.includes('1812'); // Common audio service UUIDs
                });

                if (audioServices.length === 0) {
                  console.log('No audio services found, trying first service');
                  // Если аудио сервисы не найдены, попробуем первый доступный сервис
                  if (services.length > 0) {
                    tryFirstService(services[0]);
                  } else {
                    return res.json({ 
                      status: "connected", 
                      mac: mac,
                      device: device,
                      message: `Successfully connected to ${mac} (no services found)` 
                    });
                  }
                } else {
                  console.log(`Found ${audioServices.length} potential audio services`);
                  tryFirstService(audioServices[0]);
                }
              });

              function tryFirstService(service) {
                console.log(`Discovering characteristics for service ${service.uuid}`);
                service.discoverCharacteristics([], (error, characteristics) => {
                  if (error) {
                    console.error('Characteristic discovery error:', error);
                    return res.json({ 
                      status: "connected", 
                      mac: mac,
                      device: device,
                      message: `Successfully connected to ${mac} (characteristic discovery failed)` 
                    });
                  }

                  console.log(`Found ${characteristics.length} characteristics`);
                  
                  // Ищем характеристики для записи (свойство write)
                  const writableCharacteristics = characteristics.filter(char => 
                    char.properties.includes('write') || char.properties.includes('writeWithoutResponse')
                  );

                  if (writableCharacteristics.length === 0) {
                    console.log('No writable characteristics found');
                    return res.json({ 
                      status: "connected", 
                      mac: mac,
                      device: device,
                      message: `Successfully connected to ${mac} (no writable characteristics)` 
                    });
                  }

                  console.log(`Found ${writableCharacteristics.length} writable characteristics`);
                  
                  // Пытаемся отправить команду уменьшения громкости
                  // Это может быть разной для разных устройств, пробуем несколько вариантов
                  const volumeCommands = [
                    Buffer.from([0x00, 0x01, 0x02]), // Общая команда уменьшения громкости
                    Buffer.from([0x04, 0x00, 0x01]), // Альтернативная команда
                    Buffer.from([0x02, 0x00]),       // Простая команда
                    Buffer.from('VOL-')              // Текстовая команда
                  ];

                  let commandIndex = 0;
                  
                  function tryNextCommand() {
                    if (commandIndex >= volumeCommands.length) {
                      console.log('All volume commands failed');
                      return res.json({ 
                        status: "connected", 
                        mac: mac,
                        device: device,
                        message: `Successfully connected to ${mac} (volume control failed)` 
                      });
                    }

                    const command = volumeCommands[commandIndex];
                    const char = writableCharacteristics[0];
                    
                    console.log(`Trying volume command ${commandIndex + 1}:`, command.toString('hex'));
                    
                    char.write(command, false, (error) => {
                      if (error) {
                        console.error(`Volume command ${commandIndex + 1} failed:`, error);
                        commandIndex++;
                        tryNextCommand();
                      } else {
                        console.log(`Volume command ${commandIndex + 1} succeeded`);
                        return res.json({ 
                          status: "connected", 
                          mac: mac,
                          device: device,
                          message: `Successfully connected to ${mac} and sent volume down command` 
                        });
                      }
                    });
                  }

                  tryNextCommand();
                });
              }
            }
          });
        }
      };

      noble.on('discover', onDiscover);
      
      // Убедимся что сканирование запущено
      if (noble.state === 'poweredOn') {
        noble.startScanning([], true);
        console.log('Started scanning for all devices');
      } else {
        clearTimeout(timeout);
        noble.removeListener('discover', onDiscover);
        console.log('Bluetooth not powered on, state:', noble.state);
        return res.status(500).json({ 
          error: "Bluetooth not powered on", 
          message: `Bluetooth state: ${noble.state}` 
        });
      }
      
      return; // Выходим из функции, ждем асинхронные колбэки
    }

    // Если peripheral найден, подключаемся напрямую
    peripheral.connect((error) => {
      if (error) {
        console.error(`Failed to connect to ${mac}:`, error);
        return res.status(500).json({ 
          error: "Connection failed", 
          message: `Connection failed to ${mac}: ${error.message}` 
        });
      }

      res.json({ 
        status: "connected", 
        mac: mac,
        device: device,
        message: `Successfully connected to ${mac}` 
      });
    });

  } catch (error) {
    console.error(`Error connecting to ${mac}:`, error);
    res.status(500).json({ 
      error: "Connection error", 
      message: `Error connecting to ${mac}: ${error.message}` 
    });
  }
});

// Отключение от Bluetooth устройства
app.post("/bluetooth/disconnect/:mac", async (req, res) => {
  const mac = req.params.mac.toLowerCase();
  
  try {
    // Найти peripheral в noble
    let peripheral = noble._peripherals[mac];
    
    if (!peripheral) {
      return res.status(404).json({ 
        error: "Peripheral not found", 
        message: "Device not found in noble peripherals" 
      });
    }

    peripheral.disconnect();
    console.log(`Disconnected from ${mac}`);
    res.json({ 
      status: "disconnected", 
      mac: mac,
      message: `Disconnected from ${mac}` 
    });
  } catch (error) {
    console.error(`Error disconnecting from ${mac}:`, error);
    res.status(500).json({ 
      error: "Disconnection error", 
      message: `Error disconnecting from ${mac}: ${error.message}` 
    });
  }
});

// --- BTMON ---
let btmon = null;

app.post("/btmon/start", (req, res) => {
  if (btmon) return res.json({ status: "already running" });

  btmon = spawn("btmon");

  btmon.stdout.on("data", (data) => {
    broadcast("btmon", data.toString());
  });

  btmon.on("close", () => {
    btmon = null;
  });

  res.json({ status: "started" });
});

app.post("/btmon/stop", (req, res) => {
  if (btmon) {
    btmon.kill();
    btmon = null;
  }
  res.json({ status: "stopped" });
});

//// === WIFI

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
