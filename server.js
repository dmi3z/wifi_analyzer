// server.js
const express = require("express");
const cors = require("cors");
const { spawn, exec, execSync } = require("child_process");
const fs = require("fs");
const bluetooth = require("./bluetooth");
const wifi = require("./wifi");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;

const ouiText = fs.readFileSync("oui.txt", "utf8");
const ouiMap = {};

/// ------

const dbus = require("dbus-next");
const { Variant } = dbus;
let counter = 0;

const bus = dbus.systemBus();
const interfaceName = "org.bluez.Device1";
const BLUEZ = "org.bluez";
const PROPS = "org.freedesktop.DBus.Properties";

function now() {
  return new Date().toISOString();
}

async function detector(devicePath) {
  try {
    console.log(`[${now()}] Мониторинг устройства ${devicePath}`);
    
    // Проверяем существование устройства
    const obj = await bus.getProxyObject(BLUEZ, devicePath);
    let device, props;
    
    try {
      device = obj.getInterface("org.bluez.Device1");
      props = obj.getInterface(PROPS);
    } catch (err) {
      console.error(`[${now()}] Устройство ${devicePath} не найдено или не поддерживает Device1 интерфейс:`, err.message);
      return;
    }

    // --- Текущее состояние ---
    const connected = await props.Get("org.bluez.Device1", "Connected");
    const uuids = await props.Get("org.bluez.Device1", "UUIDs");

    console.log(`[${now()}] Connected:`, connected.value);
    console.log(`[${now()}] UUIDs:`, uuids.value);

    if (uuids.value.includes("0000110b-0000-1000-8000-00805f9b34fb")) {
      console.log(`[${now()}] A2DP Sink поддерживается`);
    }

    // --- Слушаем изменения ---
    props.on("PropertiesChanged", (iface, changed) => {
      if (iface !== "org.bluez.Device1") return;

      if ("Connected" in changed) {
        const val = changed.Connected.value;
        console.log(`[${now()}] Connected changed -> ${val}`);

        if (!val) {
          console.log(`[${now()}] ⚠️ Возможный ОБРЫВ звука (disconnect)`);
        } else {
          console.log(`[${now()}] 🔌 Переподключение`);
        }
      }

      if ("UUIDs" in changed) {
        console.log(`[${now()}] UUIDs updated:`, changed.UUIDs.value);
      }
    });

    // --- Глобальный монитор транспорта ---
    bus.addMatch(
      "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'",
    );

    bus.on("message", (msg) => {
      if (msg.interface !== PROPS || msg.member !== "PropertiesChanged") return;

      const [iface, changed] = msg.body;

      if (iface !== "org.bluez.MediaTransport1") return;

      if ("State" in changed) {
        const state = changed.State.value;

        console.log(`[${now()}] A2DP Transport State -> ${state}`);

        if (state === "idle") {
          console.log(`[${now()}] ⚠️ Аудио остановлено`);
        }

        if (state === "active") {
          console.log(`[${now()}] ▶️ Идёт аудио поток`);
        }

        if (state === "pending") {
          console.log(`[${now()}] ⏳ Переключение / возможный лаг`);
        }
      }
    });

    console.log(`[${now()}] Мониторинг устройства ${devicePath} запущен`);
  } catch (error) {
    console.error(`[${now()}] Ошибка запуска детектора для ${devicePath}:`, error.message);
  }
}

async function connectDisconnectLoop(mac) {
  try {
    const devicePath = "/org/bluez/hci0/" + mac;
    console.log(`Проверка устройства ${devicePath} для цикла connect/disconnect...`);
    
    const obj = await bus.getProxyObject("org.bluez", devicePath);
    let device;
    
    try {
      device = obj.getInterface(interfaceName);
    } catch (err) {
      console.error(`Устройство ${devicePath} не найдено для цикла:`, err.message);
      return;
    }

    console.log("Начало цикла connect/disconnect...");

    while (counter !== 10) {
      console.log("Попытка подключиться...");
      try {
        await device.Connect();
      } catch (e) {
        /* игнорируем ошибки */
      }

      // Подождать 1 секунду
      await new Promise((r) => setTimeout(r, 1000));

      console.log("Отключение...");
      try {
        await device.Disconnect();
      } catch (e) {
        /* игнорируем ошибки */
      }

      // Подождать 1 секунду
      await new Promise((r) => setTimeout(r, 1000));

      counter++;
    }

    console.log("Конец цикла connect/disconnect...");
  } catch (err) {
    console.error("Ошибка при подключении к D-Bus:", err);
  }
}

///// =======

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

// Setup Bluetooth events
bluetooth.setupNobleEvents();

// SSE endpoint
app.get("/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  bluetooth.clients.push(res);

  req.on("close", () => {
    bluetooth.clients = bluetooth.clients.filter((c) => c !== res);
  });
});

app.post("/bluetooth/off", (req, res) => {
  exec("sudo rfkill block bluetooth", () => res.json({ status: "off" }));
});

app.post("/bluetooth/on", (req, res) => {
  exec("sudo rfkill unblock bluetooth", () => res.json({ status: "on" }));
});

// --- API ---

// список текущих устройств
app.get("/devices", (req, res) => {
  res.json(Object.values(bluetooth.devices));
});

// конкретное устройство
app.get("/devices/:mac", (req, res) => {
  res.json(bluetooth.devices[req.params.mac] || {});
});

// топ по RSSI
app.get("/devices/top/:n", (req, res) => {
  const n = parseInt(req.params.n);
  const sorted = Object.values(bluetooth.devices)
    .sort((a, b) => b.rssi - a.rssi)
    .slice(0, n);
  res.json(sorted);
});

// история (из RAM)
app.get("/history", (req, res) => {
  res.json(bluetooth.history.slice(-100)); // последние 100
});

// очистка
app.delete("/devices", (req, res) => {
  bluetooth.devices = {};
  bluetooth.history = [];
  res.json({ ok: true });
});

// Подключение к Bluetooth устройству по MAC адресу
app.post("/bluetooth/connect/:mac", async (req, res) => {
  const mac = req.params.mac.toLowerCase();

  try {
    // Найти устройство среди обнаруженных
    const device = Object.values(bluetooth.devices).find(
      (d) => d.mac.toLowerCase() === mac,
    );

    if (!device) {
      return res.status(404).json({
        error: "Device not found",
        message: "Device not found",
      });
    }

    // Попытка найти и подключиться к peripheral
    // Сначала проверяем в _peripherals
    let peripheral = bluetooth.noble._peripherals[mac];

    if (!peripheral) {
      // Если не нашли, попробуем найти через startScanning и ждать discovery
      console.log(`Device ${mac} not in _peripherals, starting scan...`);
      console.log(
        "Available peripherals:",
        Object.keys(bluetooth.noble._peripherals),
      );

      const timeout = setTimeout(() => {
        bluetooth.noble.stopScanning();
        bluetooth.noble.removeListener("discover", onDiscover);
        console.log(`Scan timeout for ${mac}`);
        return res.status(404).json({
          error: "Device not found after scanning",
          message: `Device ${mac} not found after 5 seconds of scanning`,
        });
      }, 5000);

      const onDiscover = (peripheral) => {
        console.log(
          `Discovered device: ${peripheral.address} (looking for ${mac})`,
        );
        if (peripheral.address.toLowerCase() === mac) {
          clearTimeout(timeout);
          bluetooth.noble.removeListener("discover", onDiscover);
          bluetooth.noble.stopScanning();

          console.log(`Found target device ${mac}, attempting connection...`);

          // Если peripheral найден, подключаемся напрямую
          // Проверяем состояние подключения
          if (peripheral.state === "connected") {
            console.log(
              `Device ${mac} already connected, checking preparation...`,
            );

            // Проверяем, готово ли устройство
            const connectedInfo = bluetooth.connectedDevices.get(mac);
            if (!connectedInfo || !connectedInfo.writableCharacteristics) {
              // Устройство еще не готово, запускаем подготовку
              return bluetooth.handleDevicePreparation(
                peripheral,
                mac,
                device,
                res,
              );
            } else {
              // Устройство уже готово к командам
              console.log(`Device ${mac} already prepared, ready for commands`);
              res.json({
                status: "connected",
                mac: mac,
                device: device,
                message: `Successfully connected to ${mac} (ready for volume commands)`,
              });
            }
          }

          peripheral.connect((error) => {
            if (error) {
              console.error(`Connection error for ${mac}:`, error);
              return res.status(500).json({
                error: "Connection failed",
                message: `Connection failed to ${mac}: ${error.message}`,
              });
            } else {
              console.log(`Successfully connected to ${mac}`);

              // После успешного подключения подготавливаем устройство для управления громкостью
              // только если это первое подключение
              const connectedInfo = bluetooth.connectedDevices.get(mac);
              if (!connectedInfo || !connectedInfo.writableCharacteristics) {
                return bluetooth.handleDevicePreparation(
                  peripheral,
                  mac,
                  device,
                  res,
                );
              } else {
                // Устройство уже готово к командам
                console.log(
                  `Device ${mac} already prepared, ready for commands`,
                );
                res.json({
                  status: "connected",
                  mac: mac,
                  device: device,
                  message: `Successfully connected to ${mac} (ready for volume commands)`,
                });
              }
            }
          });
        }
      };

      bluetooth.noble.on("discover", onDiscover);

      // Убедимся что сканирование запущено
      if (bluetooth.noble.state === "poweredOn") {
        bluetooth.noble.startScanning([], true);
        console.log("Started scanning for all devices");
      } else {
        clearTimeout(timeout);
        bluetooth.noble.removeListener("discover", onDiscover);
        bluetooth.noble.stopScanning();
        console.log("Bluetooth not powered on, state:", bluetooth.noble.state);
        return res.status(500).json({
          error: "Bluetooth not powered on",
          message: `Bluetooth state: ${bluetooth.noble.state}`,
        });
      }

      return; // Выходим из функции, ждем асинхронные колбэки
    }

    // Если peripheral найден, подключаемся напрямую
    // Проверяем состояние подключения
    if (peripheral.state === "connected") {
      console.log(
        `Device ${mac} already connected, attempting device preparation...`,
      );

      // Устройство уже подключено, подготавливаем его для управления громкостью
      return bluetooth.handleDevicePreparation(peripheral, mac, device, res);
    }

    peripheral.connect((error) => {
      if (error) {
        console.error(`Failed to connect to ${mac}:`, error);
        return res.status(500).json({
          error: "Connection failed",
          message: `Connection failed to ${mac}: ${error.message}`,
        });
      }

      // После успешного подключения проверяем, нужно ли готовить устройство
      const connectedInfo = bluetooth.connectedDevices.get(mac);
      if (!connectedInfo || !connectedInfo.writableCharacteristics) {
        // Устройство еще не готово, запускаем подготовку
        return bluetooth.handleDevicePreparation(peripheral, mac, device, res);
      } else {
        // Устройство уже готово к командам
        console.log(`Device ${mac} already prepared, ready for commands`);
        res.json({
          status: "connected",
          mac: mac,
          device: device,
          message: `Successfully connected to ${mac} (ready for volume commands)`,
        });
      }
    });
  } catch (error) {
    console.error(`Error connecting to ${mac}:`, error);
    res.status(500).json({
      error: "Connection error",
      message: `Error connecting to ${mac}: ${error.message}`,
    });
  }
});

// Отправка команды громкости
app.post("/bluetooth/volume/:mac", async (req, res) => {
  const mac = req.params.mac.toLowerCase();
  bluetooth.sendVolumeCommand(mac, req.body, res);
});

// Отключение от Bluetooth устройства
app.post("/bluetooth/disconnect/:mac", async (req, res) => {
  const mac = req.params.mac.toLowerCase();
  bluetooth.disconnectDevice(mac, res);
});

// Flood volume commands (connect + flood + disconnect)
app.post("/bluetooth/volume/:mac/flood", async (req, res) => {
  const mac = req.params.mac.toLowerCase();
  bluetooth.floodVolumeCommands(mac, res);
});

// Connect/Disconnect loop testing
app.post("/bluetooth/connect-disconnect-loop/:mac", async (req, res) => {
  const mac = req.params.mac.toLowerCase();
  const devicePath = `/org/bluez/hci0/${mac.replace(/:/g, '')}`;
  
  try {
    console.log(`Starting connect/disconnect loop for ${mac}...`);
    
    // Сначала проверим доступные устройства
    console.log("Проверка доступных устройств в BlueZ...");
    
    try {
      // Простой метод - пробуем получить интерфейс напрямую
      console.log(`Проверка устройства ${devicePath} в BlueZ...`);
      
      try {
        const testObj = await bus.getProxyObject(BLUEZ, devicePath);
        const testDevice = testObj.getInterface("org.bluez.Device1");
        console.log(`Устройство ${devicePath} найдено в BlueZ`);
        
        // Запускаем детектор для конкретного устройства
        detector(devicePath).catch((err) => {
          console.error(`Ошибка запуска детектора для ${mac}:`, err);
        });
        
        // Запускаем цикл в фоне
        connectDisconnectLoop(mac.replace(/:/g, ''));
        
        res.json({ 
          status: "loop_started", 
          mac: mac,
          devicePath: devicePath,
          message: `Connect/disconnect loop and monitoring started for ${mac}` 
        });
        
        return;
        
      } catch (deviceError) {
        console.log(`Устройство ${mac} не найдено в BlueZ: ${deviceError.message}`);
        console.log(`Пробуем сначала подключиться через Noble...`);
        
        // Пробуем подключиться через Noble чтобы зарегистрировать устройство
        const noble = require("@abandonware/noble");
        let peripheral = noble._peripherals[mac];
        
        if (!peripheral) {
          console.log(`Устройство ${mac} не в кеше Noble, проверяем подключенные устройства...`);
          
          // Проверяем все подключенные устройства
          const noble = require("@abandonware/noble");
          const connectedPeripherals = Object.values(noble._peripherals).filter(p => p.state === 'connected');
          console.log(`Подключенные устройства: ${connectedPeripherals.map(p => p.address).join(', ')}`);
          
          // Ищем среди подключенных
          const connectedDevice = connectedPeripherals.find(p => p.address.toLowerCase() === mac);
          
          if (connectedDevice) {
            console.log(`Найдено подключенное устройство: ${connectedDevice.address}`);
            peripheral = connectedDevice;
          } else {
            console.log(`Устройство ${mac} не в кеше Noble, запускаем сканирование...`);
            
            if (noble.state !== 'poweredOn') {
              return res.status(500).json({
                error: "Bluetooth not ready",
                message: `Bluetooth state: ${noble.state}. Please check Bluetooth adapter.`
              });
            }
            
            let scanTimeout;
            let found = false;
            
            const onDiscover = (p) => {
              console.log(`Scanning discovered: ${p.address} (looking for ${mac})`);
              if (p.address.toLowerCase() === mac) {
                found = true;
                peripheral = p;
                clearTimeout(scanTimeout);
                noble.removeListener('discover', onDiscover);
                noble.stopScanning();
                console.log(`Found target device ${mac} during scan`);
                
                // Подключаемся чтобы зарегистрировать в BlueZ
                peripheral.connect((error) => {
                  if (error) {
                    console.error(`Не удалось подключиться к ${mac}:`, error);
                    return res.status(500).json({
                      error: "Connection failed",
                      message: `Failed to connect to ${mac}: ${error.message}`
                    });
                  }
                  
                  console.log(`Подключились к ${mac}, теперь пробуем запустить цикл...`);
                  
                  // Ждем немного чтобы устройство зарегистрировалось в BlueZ
                  setTimeout(() => {
                    // Запускаем детектор для конкретного устройства
                    detector(devicePath).catch((err) => {
                      console.error(`Ошибка запуска детектора для ${mac}:`, err);
                    });
                    
                    // Запускаем цикл в фоне
                    connectDisconnectLoop(mac.replace(/:/g, ''));
                    
                    res.json({ 
                      status: "loop_started", 
                      mac: mac,
                      devicePath: devicePath,
                      message: `Connect/disconnect loop and monitoring started for ${mac}` 
                    });
                  }, 2000);
                });
              }
            };
            
            scanTimeout = setTimeout(() => {
              noble.removeListener('discover', onDiscover);
              noble.stopScanning();
              console.log(`Scan timeout for ${mac}`);
              
              return res.status(404).json({
                error: "Device not found",
                message: `Device ${mac} not found after 5 seconds of scanning. Please make sure device is powered on and within range.`,
                suggestion: "Try connecting to the device first using /bluetooth/connect/:mac endpoint"
              });
            }, 5000);
            
            noble.on('discover', onDiscover);
            noble.startScanning([], true);
            console.log(`Started scanning for device ${mac}...`);
            
            return; // Ждем сканирование
          }
        }
        
        console.log(`Найдено устройство в Noble кеше: ${peripheral.address}`);
        
        // Проверяем состояние подключения
        if (peripheral.state === 'connected') {
          console.log(`Устройство ${mac} уже подключено, сразу запускаем детектор...`);
          
          // Ждем немного чтобы устройство зарегистрировалось в BlueZ
          setTimeout(() => {
            // Запускаем детектор для конкретного устройства
            detector(devicePath).catch((err) => {
              console.error(`Ошибка запуска детектора для ${mac}:`, err);
            });
            
            // Запускаем цикл в фоне
            connectDisconnectLoop(mac.replace(/:/g, ''));
            
            res.json({ 
              status: "loop_started", 
              mac: mac,
              devicePath: devicePath,
              message: `Connect/disconnect loop and monitoring started for ${mac} (device already connected)` 
            });
          }, 2000);
          
          return;
        }
        
        // Подключаемся чтобы зарегистрировать в BlueZ
        peripheral.connect((error) => {
          if (error) {
            console.error(`Не удалось подключиться к ${mac}:`, error);
            return res.status(500).json({
              error: "Connection failed",
              message: `Failed to connect to ${mac}: ${error.message}`
            });
          }
          
          console.log(`Подключились к ${mac}, теперь пробуем запустить цикл...`);
          
          // Ждем немного чтобы устройство зарегистрировалось в BlueZ
          setTimeout(() => {
            // Запускаем детектор для конкретного устройства
            detector(devicePath).catch((err) => {
              console.error(`Ошибка запуска детектора для ${mac}:`, err);
            });
            
            // Запускаем цикл в фоне
            connectDisconnectLoop(mac.replace(/:/g, ''));
            
            res.json({ 
              status: "loop_started", 
              mac: mac,
              devicePath: devicePath,
              message: `Connect/disconnect loop and monitoring started for ${mac}` 
            });
          }, 2000);
        });
        
        return; // Ждем подключения
      }
      
    } catch (bluezError) {
      console.error(`Ошибка проверки BlueZ:`, bluezError);
      return res.status(500).json({
        error: "BlueZ error",
        message: `Error checking BlueZ: ${bluezError.message}`
      });
    }
    
  } catch (error) {
    console.error(`Error starting loop for ${mac}:`, error);
    res.status(500).json({ 
      error: "Loop start failed", 
      message: `Error starting loop for ${mac}: ${error.message}` 
    });
  }
});

// Показать доступные устройства в BlueZ
app.get("/bluetooth/bluez-devices", async (req, res) => {
  try {
    console.log("Получение списка устройств из BlueZ...");
    
    // Получаем корневой объект BlueZ
    const obj = await bus.getProxyObject(BLUEZ, "/org/bluez");
    const manager = obj.getInterface("org.freedesktop.DBus.ObjectManager");
    
    // Получаем все объекты
    const objects = await manager.GetManagedObjects();
    const devices = [];
    
    for (const [path, interfaces] of Object.entries(objects)) {
      if (interfaces["org.bluez.Device1"]) {
        const deviceProps = interfaces["org.bluez.Device1"];
        devices.push({
          path: path,
          address: deviceProps.Address || "Unknown",
          name: deviceProps.Name || "Unknown",
          alias: deviceProps.Alias || "Unknown",
          connected: deviceProps.Connected || false,
          paired: deviceProps.Paired || false,
          trusted: deviceProps.Trusted || false,
          uuids: deviceProps.UUIDs || []
        });
      }
    }
    
    console.log(`Найдено ${devices.length} устройств в BlueZ`);
    
    res.json({ 
      status: "success", 
      devices: devices,
      message: `Found ${devices.length} devices in BlueZ` 
    });
  } catch (error) {
    console.error("Error getting BlueZ devices:", error);
    res.status(500).json({ 
      error: "Failed to get devices", 
      message: `Error getting BlueZ devices: ${error.message}` 
    });
  }
});

// --- BTMON ---
let btmon = null;

app.post("/btmon/start", (req, res) => {
  if (btmon) return res.json({ status: "already running" });

  btmon = spawn("btmon");

  btmon.stdout.on("data", (data) => {
    bluetooth.broadcast("btmon", data.toString());
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
    const result = wifi.switchToMonitorMode(iface);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to enable monitor mode" });
  }
});

app.get("/wlanconnection", (req, res) => {
  try {
    const interfaces = wifi.getWlanConnection();
    res.json(interfaces);
  } catch (err) {
    res.status(500).json({ error: "Failed to check Wi-Fi connection" });
  }
});

// Switch back to managed mode
app.post("/mode/managed", (req, res) => {
  const iface = req.body.iface || "wlan2";
  try {
    const result = wifi.switchToManagedMode(iface);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to switch to managed mode" });
  }
});

// Set target BSSID and channel
app.post("/target", (req, res) => {
  const { bssid, channel, iface } = req.body;
  try {
    const result = wifi.setTarget(bssid, channel, iface);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
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
        ...wifi.stats,
        clients: Array.from(wifi.stats.clients),
        target: wifi.currentTarget,
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
    const interfaces = wifi.getWlanInterfaces();
    res.json(interfaces);
  } catch (err) {
    res.status(500).json({ error: "Failed to get Wi-Fi interfaces" });
  }
});

// ==========================
// Wi-Fi scan endpoint (original version, unchanged)
// ==========================
app.get("/wifi", async (req, res) => {
  try {
    const results = await wifi.scanWifi();
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================
// Start server
// ==========================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Wi-Fi analyzer server running on http://localhost:${PORT}`);
});
