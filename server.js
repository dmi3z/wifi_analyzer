const express = require("express");
const { exec } = require("child_process");

const app = express();
const PORT = 3000;

app.get("/wifi", (req, res) => {
  const WIFI_INTERFACE = req.query.wlan || "wlan0";
  exec(`sudo iw dev ${WIFI_INTERFACE} scan`, (error, stdout, stderr) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Scan failed", details: stderr });
    }

    const networks = parseIwScan(stdout);
    const filteredNetworks = networks.filter(
      (network) => network.bssid !== "Load:",
    );
    res.json(filteredNetworks);
  });
});

// convert freq (MHz) to channel number Wi-Fi
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

function parseIwScan(data) {
  const lines = data.split("\n");
  const networks = [];
  let current = null;

  lines.forEach((line) => {
    line = line.trim();

    if (line.startsWith("BSS ")) {
      if (current) networks.push(current);
      const bssid = line.split(" ")[1];
      current = {
        bssid,
        ssid: "",
        frequency: "",
        channel: null,
        signal: "",
        flags: [],
        rates: [],
        encryption: false,
        is5G: false,
      };
    } else if (!current) {
      return;
    } else if (line.startsWith("SSID:")) {
      current.ssid = line.slice(5).trim();
    } else if (line.startsWith("freq:")) {
      current.frequency = line.slice(5).trim();
      current.channel = freqToChannel(current.frequency);
    } else if (line.startsWith("signal:")) {
      current.signal = line.slice(7).trim();
    } else if (line.startsWith("flags:")) {
      current.flags = line
        .slice(6)
        .trim()
        .split(/\s+/)
        .filter((f) => f.length > 0);
      if (current.flags.some((f) => /WPA|WEP|RSN/.test(f))) {
        current.encryption = true;
      }
    } else if (line.startsWith("supported rates:")) {
      const rates = line
        .slice(16)
        .trim()
        .split(/\s+/)
        .map((r) => r.replace(/[.+*]/g, ""));
      current.rates.push(...rates);
    } else if (line.startsWith("RSN:") || line.includes("WPA")) {
      current.encryption = true;
    }
    current.is5G = current.channel >= 36;
  });

  if (current) networks.push(current);
  return networks;
}

app.listen(PORT, () => {
  console.log(`WiFi analyzer server running on http://localhost:${PORT}`);
});
