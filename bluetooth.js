// Bluetooth module for wifi_analyzer
const noble = require("@abandonware/noble");

// Global variables
let connectedDevices = new Map(); // Храним подключенные устройства
let devices = {};
let history = [];
let clients = [];

// BLE functions
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

// SSE broadcast function
function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  clients.forEach((c) => c.write(payload));
}

// Noble event handlers
function setupNobleEvents() {
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
}

// Device preparation function
function handleDevicePreparation(peripheral, mac, device, res) {
  console.log(`Starting device preparation for ${mac}`);
  
  // Добавляем устройство в список подключенных
  connectedDevices.set(mac, { peripheral, device, lastRSSI: device.rssi });
  
  // Добавляем общий таймаут для всего процесса
  const overallTimeout = setTimeout(() => {
    console.log(`Device preparation timeout for ${mac}`);
    return res.json({ 
      status: "connected", 
      mac: mac,
      device: device,
      message: `Successfully connected to ${mac} (device preparation timeout)` 
    });
  }, 5000); // 5 секунд на весь процесс

  // Попытка найти сервисы и характеристики для управления громкостью
  peripheral.discoverServices([], (error, services) => {
    if (error) {
      clearTimeout(overallTimeout);
      console.error('Service discovery error:', error);
      return res.json({ 
        status: "connected", 
        mac: mac,
        device: device,
        message: `Successfully connected to ${mac} (service discovery failed)` 
      });
    }

    console.log(`Found ${services.length} services for ${mac}`);
    
    // Выводим все найденные сервисы
    services.forEach((service, index) => {
      console.log(`Service ${index + 1}: ${service.uuid}`);
    });
    
    // Ищем сервисы, связанные с аудио
    const audioServices = services.filter(service => {
      const uuid = service.uuid.toLowerCase();
      return uuid.includes('audio') || uuid.includes('volume') || 
             uuid.includes('180b') || uuid.includes('1812') || // Common audio service UUIDs
             uuid.includes('fe2c') || // Apple Headphone Service
             uuid.includes('657863656c706f696e742e'); // ExcelPoint custom service
    });

    if (audioServices.length === 0) {
      console.log('No audio services found, trying first service');
      // Если аудио сервисы не найдены, пробуем первый доступный сервис
      if (services.length > 0) {
        tryFirstService(services[0]);
      } else {
        clearTimeout(overallTimeout);
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
        clearTimeout(overallTimeout);
        console.error('Characteristic discovery error:', error);
        return res.json({ 
          status: "connected", 
          mac: mac,
          device: device,
          message: `Successfully connected to ${mac} (characteristic discovery failed)` 
        });
      }

      console.log(`Found ${characteristics.length} characteristics`);
      
      // Выводим все найденные характеристики
      characteristics.forEach((char, index) => {
        let description = '';
        if (char.uuid === '2a05') description = ' (Service Changed - уведомления об изменении сервисов)';
        else if (char.uuid === '2b3a') description = ' (Volume State - состояние громкости)';
        else if (char.uuid === '2b29') description = ' (Volume Control - управление громкостью)';
        
        console.log(`Characteristic ${index + 1}: ${char.uuid}${description} - Properties: ${char.properties.join(', ')}`);
      });
      
      // Ищем характеристики для записи (свойство write)
      const writableCharacteristics = characteristics.filter(char => 
        char.properties.includes('write') || char.properties.includes('writeWithoutResponse')
      );

      if (writableCharacteristics.length === 0) {
        clearTimeout(overallTimeout);
        console.log('No writable characteristics found');
        return res.json({ 
          status: "connected", 
          mac: mac,
          device: device,
          message: `Successfully connected to ${mac} (no writable characteristics)` 
        });
      }

      console.log(`Found ${writableCharacteristics.length} writable characteristics`);
      
      // Сохраняем writable characteristics для будущего использования
      const connectedInfo = connectedDevices.get(mac);
      if (connectedInfo) {
        connectedInfo.writableCharacteristics = writableCharacteristics;
        connectedDevices.set(mac, connectedInfo);
      }
      
      clearTimeout(overallTimeout);
      return res.json({ 
        status: "connected", 
        mac: mac,
        device: device,
        message: `Successfully connected to ${mac} (ready for volume commands)` 
      });
    });
  }
}

// Volume command function
function sendVolumeCommand(mac, { command, commandType, action }, res) {
  try {
    // Проверяем что устройство подключено
    const connectedInfo = connectedDevices.get(mac);
    if (!connectedInfo) {
      return res.status(404).json({ 
        error: "Device not connected", 
        message: "Device not found in connected devices" 
      });
    }

    const { writableCharacteristics, readableCharacteristics, peripheral } = connectedInfo;
    
    // Если нужно сначала прочитать характеристики
    if (action === 'read' || !writableCharacteristics) {
      console.log(`Reading characteristics for ${mac}...`);
      
      // Находим все характеристики для чтения
      peripheral.discoverServices([], (error, services) => {
        if (error) {
          return res.status(500).json({ error: "Service discovery failed" });
        }

        let allCharacteristics = [];
        let servicesProcessed = 0;

        services.forEach(service => {
          service.discoverCharacteristics([], (error, characteristics) => {
            if (error) return;
            
            allCharacteristics.push(...characteristics);
            servicesProcessed++;
            
            if (servicesProcessed === services.length) {
              // Фильтруем читаемые характеристики
              const readable = allCharacteristics.filter(char => 
                char.properties.includes('read')
              );
              
              // Сохраняем для будущего использования
              connectedInfo.readableCharacteristics = readable;
              if (writableCharacteristics) {
                connectedInfo.writableCharacteristics = writableCharacteristics;
              }
              connectedDevices.set(mac, connectedInfo);
              
              // Читаем первые несколько характеристик
              readCharacteristics(readable.slice(0, 5), 0, [], res, mac);
            }
          });
        });
      });
      
      function readCharacteristics(characteristics, index, results, res, mac) {
        if (index >= characteristics.length) {
          return res.json({
            status: "read_complete",
            mac: mac,
            characteristics: results,
            message: `Read ${results.length} characteristics`
          });
        }

        const char = characteristics[index];
        char.read((error, data) => {
          if (!error && data) {
            results.push({
              uuid: char.uuid,
              properties: char.properties,
              data: data.toString('hex'),
              dataBuffer: Array.from(data)
            });
          }
          
          readCharacteristics(characteristics, index + 1, results, res, mac);
        });
      }
      
      return;
    }

    if (!writableCharacteristics || writableCharacteristics.length === 0) {
      return res.status(404).json({ 
        error: "No writable characteristics", 
        message: "Device connected but no writable characteristics found" 
      });
    }

    // Расширенный набор команд для разных устройств
    let volumeCommands = [];
    
    if (commandType === 'down') {
      volumeCommands = [
        Buffer.from([0x01]),             // JBL volume down (single byte)
        Buffer.from([0x00]),             // JBL volume down alternative
        Buffer.from([0x01, 0x00]),       // Volume Down для 2b29
        Buffer.from([0x00, 0x01]),       // Уменьшение на 1
        Buffer.from([0x02]),             // JBL command 2
        Buffer.from([0x01, 0x02]),       // Уменьшение громкости v2
        Buffer.from([0x03, 0x01]),       // Volume down альтернатива
        Buffer.from([0x80, 0x00]),       // Установка 0%
        Buffer.from([0x00, 0x80, 0x00]), // 3-byte command
        Buffer.from([0xA0, 0x01])        // Alternative format
      ];
    } else if (commandType === 'up') {
      volumeCommands = [
        Buffer.from([0x02]),             // JBL volume up (single byte)
        Buffer.from([0xFF]),             // JBL volume up alternative
        Buffer.from([0x02, 0x00]),       // Volume Up
        Buffer.from([0x00, 0xFF]),       // Увеличение на 1
        Buffer.from([0x03]),             // JBL command 3
        Buffer.from([0xFF, 0x00]),       // Максимальная громкость
        Buffer.from([0x00, 0xFF, 0x00]), // 3-byte max
        Buffer.from([0xA0, 0x02])        // Alternative up
      ];
    } else if (commandType === 'set' && command) {
      // Пользовательская команда в hex
      try {
        volumeCommands = [Buffer.from(command, 'hex')];
      } catch (e) {
        return res.status(400).json({ 
          error: "Invalid command", 
          message: "Command must be valid hex string" 
        });
      }
    } else if (commandType === 'mute') {
      volumeCommands = [
        Buffer.from([0x00]),             // JBL mute (single byte)
        Buffer.from([0x00, 0x00]),       // Mute/Min volume
        Buffer.from([0x80]),             // JBL mute alternative
        Buffer.from([0x80, 0x00]),       // Alternative mute
        Buffer.from([0xA0, 0x00])        // Another mute format
      ];
    } else {
      // По умолчанию - JBL оптимизированный набор
      volumeCommands = [
        Buffer.from([0x01]),             // JBL volume down (single byte) - ПРИОРИТЕТ
        Buffer.from([0x00]),             // JBL volume down alternative
        Buffer.from([0x02]),             // JBL volume up (для проверки)
        Buffer.from([0xFF]),             // JBL volume up alternative
        Buffer.from([0x01, 0x00]),       // Volume Down для 2b29
        Buffer.from([0x02, 0x00]),       // Volume Up (для проверки)
        Buffer.from([0x00, 0x80]),       // Установка громкости 50%
        Buffer.from([0x00, 0x00]),       // Минимальная громкость
        Buffer.from([0x00, 0x01]),       // Уменьшение на 1
        Buffer.from([0xFF, 0x00]),       // Максимальная громкость
        Buffer.from([0x01, 0x02]),       // Уменьшение громкости v2
        Buffer.from([0x03, 0x01])        // Volume down альтернатива
      ];
    }

    let commandIndex = 0;
    
    function tryNextCommand() {
      if (commandIndex >= volumeCommands.length) {
        console.log('All volume commands failed');
        return res.json({ 
          status: "failed", 
          mac: mac,
          message: `All ${volumeCommands.length} volume commands failed` 
        });
      }

      const cmd = volumeCommands[commandIndex];
      const char = writableCharacteristics[0];
      
      console.log(`Trying volume command ${commandIndex + 1}/${volumeCommands.length}:`, cmd.toString('hex'), `(${cmd.length} bytes)`);
      
      // Добавляем таймаут для операции записи
      const writeTimeout = setTimeout(() => {
        console.error(`Volume command ${commandIndex + 1} timeout after 3s`);
        commandIndex++;
        tryNextCommand();
      }, 3000); // 3 секунды на ответ
      
      char.write(cmd, false, (error) => {
        clearTimeout(writeTimeout);
        if (error) {
          console.error(`Volume command ${commandIndex + 1} failed:`, error.message || error);
          commandIndex++;
          tryNextCommand();
        } else {
          console.log(`Volume command ${commandIndex + 1} succeeded:`, cmd.toString('hex'));
          return res.json({ 
            status: "success", 
            mac: mac,
            command: cmd.toString('hex'),
            commandIndex: commandIndex + 1,
            totalCommands: volumeCommands.length,
            message: `Volume command sent successfully (attempt ${commandIndex + 1}/${volumeCommands.length})` 
          });
        }
      });
    }

    tryNextCommand();
  } catch (error) {
    console.error(`Error sending volume command to ${mac}:`, error);
    res.status(500).json({ 
      error: "Volume command error", 
      message: `Error sending volume command to ${mac}: ${error.message}` 
    });
  }
}

// Disconnect function
function disconnectDevice(mac, res) {
  try {
    // Найти peripheral в noble
    let peripheral = noble._peripherals[mac];
    
    if (!peripheral) {
      return res.status(404).json({ 
        error: "Peripheral not found", 
        message: "Device not found in noble peripherals" 
      });
    }

    // Останавливаем RSSI обновления
    const connectedInfo = connectedDevices.get(mac);
    if (connectedInfo && connectedInfo.updateInterval) {
      clearInterval(connectedInfo.updateInterval);
      console.log(`Stopped RSSI updates for ${mac}`);
    }
    
    // Удаляем из списка подключенных
    connectedDevices.delete(mac);

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
}

// Export functions and data
module.exports = {
  setupNobleEvents,
  handleDevicePreparation,
  sendVolumeCommand,
  disconnectDevice,
  connectedDevices,
  devices,
  history,
  clients,
  broadcast,
  noble
};
