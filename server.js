// server.js
const express = require("express");
const cors = require("cors");
const { spawn, exec, execSync } = require("child_process");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;

// ==========================
// Global variables
// ==========================
let currentTarget = {
  bssid: null,
  channel: null,
  iface: "wlan2"
};

let tsharkProcess = null;

let stats = {
  totalPackets: 0,
  handshakeCount: 0,
  clients: new Set()
};

// ==========================
// Utility functions
// ==========================
function resetStats() {
  stats = {
    totalPackets: 0,
    handshakeCount: 0,
    clients: new Set()
  };
}

function stopTshark() {
  if (tsharkProcess) {
    console.log("Stopping old tshark...");
    tsharkProcess.kill();
    tsharkProcess = null;
  }
}
function freqToChannel(freq) {
  freq = parseInt(freq, 10);
  if (freq >= 2412 && freq <= 2472) {
    return Math.floor((freq - 2407) / 5); // 2.4 GHz
  } else if (freq === 2484) {
    return 14;
  } else if (freq >= 5180 && freq <= 5825) {
    return Math.floor((freq - 5000) / 5); // 5 GHz
  }
  return null;
}
function startTshark(bssid, channel, iface) {
  console.log(`Starting capture for ${bssid} on channel ${channel}`);
  execSync(`sudo iw dev ${iface} set channel ${channel}`);
  resetStats();

  tsharkProcess = spawn("sudo", [
    "tshark",
    "-i", iface,
    "-Y", `wlan.bssid == ${bssid}`,
    "-T", "json"
  ]);

  tsharkProcess.stdout.on("data", (data) => {
    try {
      const packets = JSON.parse(data.toString());
      packets.forEach(pkt => {
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
  if (!bssid || !channel) return res.status(400).json({ error: "bssid and channel are required" });

  const newIface = iface || currentTarget.iface;

  currentTarget = {
    bssid: bssid.toUpperCase(),
    channel,
    iface: newIface
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
    Connection: "keep-alive"
  });

  const interval = setInterval(() => {
    res.write(`data: ${JSON.stringify({
      ...stats,
      clients: Array.from(stats.clients),
      target: currentTarget
    })}\n\n`);
  }, 1000);

  req.on("close", () => {
    clearInterval(interval);
    console.log("Client disconnected from SSE");
  });
});

// Get list of Wi-Fi interfaces
app.get("/wlan", (req, res) => {
  try {
    const output = execSync("iw dev | grep Interface | awk '{print $2}'").toString();
    const interfaces = output.split("\n").map(i => i.trim()).filter(i => i.length > 0);
    res.json(interfaces);
  } catch (err) {
    console.error("Failed to get Wi-Fi interfaces");
    res.status(500).json({ error: "Failed to get Wi-Fi interfaces" });
  }
});

// ==========================
// Wi-Fi scan endpoint (original version, unchanged)
// ==========================
const expressExec = require("child_process").exec;


app.get("/wifi", (req, res) => {
  const WIFI_INTERFACE = req.query.wlan || "wlan1";

  exec(`sudo iw dev ${WIFI_INTERFACE} scan`, (error, stdout, stderr) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Scan failed", details: stderr });
    }

    const lines = stdout.split("\n");
    const networks = [];
    let current = null;
    let inRSN = false;

    lines.forEach(line => {
      const trimmed = line.trim();

      if (trimmed.startsWith("BSS ")) {
        if (current) {
          // Определяем финальный encryption перед добавлением
          if (current.hasWPA3) current.encryption = "WPA3";
          else if (current.hasWPA2) current.encryption = "WPA2";
          else if (current.hasWPA) current.encryption = "WPA";
          else if (current.hasWEP) current.encryption = "WEP";
          else current.encryption = "opened";

          networks.push(current);
        }

        const bssid = trimmed.split(" ")[1].split("(")[0].trim();
        current = {
          bssid,
          ssid: "",
          frequency: "",
          channel: null,
          signal: "",
          encryption: "opened",
          hasWPA3: false,
          hasWPA2: false,
          hasWPA: false,
          hasWEP: false,
          rates: [],
          is5G: false
        };
        inRSN = false;

      } else if (!current) return;

      // SSID
      else if (trimmed.startsWith("SSID:")) current.ssid = trimmed.slice(5).trim();

      // Частота и канал
      else if (trimmed.startsWith("freq:")) {
        current.frequency = trimmed.slice(5).trim();
        current.channel = freqToChannel(current.frequency);
        current.is5G = current.channel >= 36;
      }

      // Сила сигнала
      else if (trimmed.startsWith("signal:")) current.signal = trimmed.slice(7).trim();

      // Поддерживаем блок RSN (WPA2)
      else if (trimmed.includes("RSN:")) inRSN = true;
      else if (inRSN) {
        if (trimmed.includes("PSK") || trimmed.includes("CCMP")) current.hasWPA2 = true;
        if (trimmed === "") inRSN = false; // пустая строка — конец блока
      }

      // WPA (WPA1)
      else if (trimmed.includes("WPA Version")) current.hasWPA = true;

      // WEP
      else if (trimmed.includes("WEP")) current.hasWEP = true;

      // Поддерживаемые скорости
      else if (trimmed.startsWith("supported rates:")) {
        const rates = trimmed
          .slice(16)
          .trim()
          .split(/\s+/)
          .map(r => r.replace(/[.+*]/g, ""));
        current.rates.push(...rates);
      }
    });

    // Финальный текущий BSS
    if (current) {
      if (current.hasWPA3) current.encryption = "WPA3";
      else if (current.hasWPA2) current.encryption = "WPA2";
      else if (current.hasWPA) current.encryption = "WPA";
      else if (current.hasWEP) current.encryption = "WEP";
      else current.encryption = "opened";

      networks.push(current);
    }

    // Фильтруем пустые SSID
    const filteredNetworks = networks.filter(net => net.bssid && net.ssid !== "");
    res.json(filteredNetworks);
  });
});



// ==========================
// Start server
// ==========================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Wi-Fi analyzer server running on http://localhost:${PORT}`);
});
