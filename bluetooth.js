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
        Buffer.from([0x01, 0x00]),       // 2b29 Volume Down (2 bytes) - ПРИОРИТЕТ
        Buffer.from([0x00, 0x01]),       // Уменьшение на 1
        Buffer.from([0x01]),             // JBL volume down (single byte)
        Buffer.from([0x00]),             // JBL volume down alternative
        Buffer.from([0x02]),             // ExcelPoint volume down
        Buffer.from([0x03]),             // ExcelPoint volume down v2
        Buffer.from([0x01, 0x02]),       // Уменьшение громкости v2
        Buffer.from([0x03, 0x01]),       // Volume down альтернатива
        Buffer.from([0x80, 0x00]),       // Установка 0%
        Buffer.from([0x00, 0x80, 0x00]), // 3-byte command
        Buffer.from([0xA0, 0x01])        // Alternative format
      ];
    } else if (commandType === 'up') {
      volumeCommands = [
        Buffer.from([0x02, 0x00]),       // 2b29 Volume Up (2 bytes) - ПРИОРИТЕТ
        Buffer.from([0x00, 0xFF]),       // Увеличение на 1
        Buffer.from([0x02]),             // JBL volume up (single byte)
        Buffer.from([0xFF]),             // JBL volume up alternative
        Buffer.from([0x01]),             // ExcelPoint volume up
        Buffer.from([0x04]),             // ExcelPoint volume up v2
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
        Buffer.from([0x00, 0x00]),       // 2b29 Mute (2 bytes) - ПРИОРИТЕТ
        Buffer.from([0x00]),             // JBL mute (single byte)
        Buffer.from([0x05]),             // ExcelPoint mute
        Buffer.from([0x80]),             // JBL mute alternative
        Buffer.from([0x80, 0x00]),       // Alternative mute
        Buffer.from([0xA0, 0x00])        // Another mute format
      ];
    } else {
      // По умолчанию - 2b29 оптимизированный набор
      volumeCommands = [
        Buffer.from([0x01, 0x00]),       // 2b29 Volume Down (2 bytes) - ПРИОРИТЕТ
        Buffer.from([0x02, 0x00]),       // 2b29 Volume Up (2 bytes) - ПРИОРИТЕТ
        Buffer.from([0x00, 0x00]),       // 2b29 Mute (2 bytes) - ПРИОРИТЕТ
        Buffer.from([0x00, 0x01]),       // Уменьшение на 1
        Buffer.from([0x00, 0xFF]),       // Увеличение на 1
        Buffer.from([0x01]),             // JBL volume down (single byte)
        Buffer.from([0x02]),             // JBL volume up (single byte)
        Buffer.from([0x00]),             // JBL volume down alternative
        Buffer.from([0xFF]),             // JBL volume up alternative
        Buffer.from([0x00, 0x80]),       // Установка громкости 50%
        Buffer.from([0x80, 0x00]),       // Alternative mute
        Buffer.from([0x01, 0x02]),       // Уменьшение громкости v2
        Buffer.from([0x03, 0x01]),       // Volume down альтернатива
        Buffer.from([0x10]),             // JBL specific command 1
        Buffer.from([0x20]),             // JBL specific command 2
        Buffer.from([0x30]),             // JBL specific command 3
        Buffer.from([0x40]),             // JBL specific command 4
        Buffer.from([0x50]),             // JBL specific command 5
        Buffer.from([0x60]),             // JBL specific command 6
        Buffer.from([0x70]),             // JBL specific command 7
        Buffer.from([0x80]),             // JBL specific command 8
        Buffer.from([0x90]),             // JBL specific command 9
        Buffer.from([0xA0]),             // JBL specific command 10
        Buffer.from([0xB0]),             // JBL specific command 11
        Buffer.from([0xC0]),             // JBL specific command 12
        Buffer.from([0xD0]),             // JBL specific command 13
        Buffer.from([0xE0]),             // JBL specific command 14
        Buffer.from([0xF0])              // JBL specific command 15
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
      // Используем правильную характеристику для JBL - 2b29 (Volume Control)
      const char = writableCharacteristics.find(c => 
        c.uuid === '2b29'
      ) || writableCharacteristics.find(c => 
        c.uuid === '657863656c706f696e742e636e6c0002'
      ) || writableCharacteristics[0];
      
      console.log(`Trying volume command ${commandIndex + 1}/${volumeCommands.length}:`, cmd.toString('hex'), `(${cmd.length} bytes) on characteristic ${char.uuid}`);
      
      // Добавляем диагностику перед записью
      console.log(`Characteristic properties: ${char.properties.join(', ')}`);
      console.log(`Using writeWithoutResponse: ${useWithoutResponse}`);
      console.log(`Current value of ${char.uuid}:`, char.uuid === '2b29' ? '00 (from read)' : 'unknown');
      
      // Добавляем таймаут для операции записи
      const writeTimeout = setTimeout(() => {
        console.error(`Volume command ${commandIndex + 1} timeout after 3s`);
        commandIndex++;
        tryNextCommand();
      }, 3000); // 3 секунды на ответ
      
      // Для 2b29 используем write с ответом, для ExcelPoint - writeWithoutResponse
      const useWithoutResponse = char.uuid === '2b29' ? false : char.properties.includes('writeWithoutResponse');
      char.write(cmd, useWithoutResponse, (error) => {
        clearTimeout(writeTimeout);
        if (error) {
          console.error(`Volume command ${commandIndex + 1} failed:`, error.message || error);
          commandIndex++;
          tryNextCommand();
        } else {
          console.log(`Volume command ${commandIndex + 1} succeeded:`, cmd.toString('hex'));
          console.log(`Command written to characteristic ${char.uuid} using ${useWithoutResponse ? 'writeWithoutResponse' : 'write'} method`);
          return res.json({ 
            status: "success", 
            mac: mac,
            command: cmd.toString('hex'),
            commandIndex: commandIndex + 1,
            totalCommands: volumeCommands.length,
            characteristic: char.uuid,
            method: useWithoutResponse ? 'writeWithoutResponse' : 'write',
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

// Flood volume commands function
function floodVolumeCommands(mac, res) {
  try {
    console.log(`Starting flood volume commands for ${mac}...`);
    
    const noble = require("@abandonware/noble");
    let peripheral = noble._peripherals[mac];
    
    if (!peripheral) {
      console.log(`Device ${mac} not in _peripherals, starting aggressive scan...`);
      console.log('Available peripherals in cache:', Object.keys(noble._peripherals));
      
      let scanTimeout;
      let found = false;
      
      const onDiscover = (p) => {
        console.log(`Discovered device during flood scan: ${p.address} (looking for ${mac})`);
        if (p.address.toLowerCase() === mac) {
          found = true;
          peripheral = p;
          clearTimeout(scanTimeout);
          noble.removeListener('discover', onDiscover);
          noble.stopScanning();
          console.log(`Found target device ${mac}, starting flood...`);
          startFloodSession();
        }
      };
      
      scanTimeout = setTimeout(() => {
        noble.removeListener('discover', onDiscover);
        noble.stopScanning();
        console.log(`Scan completed. Devices discovered during scan: ${found ? 'Target found' : 'Target not found'}`);
        
        if (!found) {
          // Пробуем еще раз с перезагрузкой сканирования
          console.log('First scan failed, trying second scan...');
          setTimeout(() => {
            if (noble.state === 'poweredOn') {
              noble.startScanning([], true);
              console.log('Started second scan attempt');
              
              setTimeout(() => {
                noble.stopScanning();
                noble.removeListener('discover', onDiscover);
                
                if (!found) {
                  return res.status(404).json({ 
                    error: "Peripheral not found", 
                    message: `Device ${mac} not found after 10 seconds of scanning. Make sure device is powered on and within range.` 
                  });
                }
              }, 5000);
            }
          }, 1000);
        }
      }, 5000);
      
      noble.on('discover', onDiscover);
      
      if (noble.state === 'poweredOn') {
        // Сначала останавливаем текущее сканирование если есть
        noble.stopScanning();
        setTimeout(() => {
          noble.startScanning([], true);
          console.log('Started aggressive scanning for flood target device');
        }, 100);
      } else {
        clearTimeout(scanTimeout);
        noble.removeListener('discover', onDiscover);
        return res.status(500).json({ 
          error: "Bluetooth not powered on", 
          message: `Bluetooth state: ${noble.state}. Please check Bluetooth adapter.` 
        });
      }
    } else {
      console.log(`Device ${mac} found in _peripherals, starting flood...`);
      startFloodSession();
    }

    const floodCommands = [
      Buffer.from([0x01]),             // Single byte commands
      Buffer.from([0x02]), 
      Buffer.from([0x00]),
      Buffer.from([0xFF]),
      Buffer.from([0x01, 0x00]),       // 2-byte commands
      Buffer.from([0x02, 0x00]),
      Buffer.from([0x00, 0x00]),
      Buffer.from([0x00, 0x01]),
      Buffer.from([0x00, 0xFF]),
      Buffer.from([0x01, 0x02]),
      Buffer.from([0x03, 0x01]),
      Buffer.from([0x00, 0x80]),
      Buffer.from([0x80, 0x00]),
      Buffer.from([0x10]),             // JBL specific
      Buffer.from([0x20]),
      Buffer.from([0x30]),
      Buffer.from([0x40]),
      Buffer.from([0x50]),
      Buffer.from([0x60]),
      Buffer.from([0x70]),
      Buffer.from([0x80]),
      Buffer.from([0x90]),
      Buffer.from([0xA0]),
      Buffer.from([0xB0]),
      Buffer.from([0xC0]),
      Buffer.from([0xD0]),
      Buffer.from([0xE0]),
      Buffer.from([0xF0])
    ];

    let commandIndex = 0;
    let floodInterval;
    let isConnected = false;
    let writableCharacteristics = [];

    function startFloodSession() {
      // Функция для запуска флуда
      function startFlood() {
        console.log(`Starting flood with ${floodCommands.length} commands for 10 seconds...`);
        
        floodInterval = setInterval(() => {
          if (commandIndex >= floodCommands.length) {
            commandIndex = 0; // Зацикливаем команды
          }

          const cmd = floodCommands[commandIndex];
          
          // Пишем во все writable характеристики
          writableCharacteristics.forEach((char, index) => {
            const useWithoutResponse = char.properties.includes('writeWithoutResponse');
            
            try {
              char.write(cmd, useWithoutResponse, (error) => {
                if (error) {
                  console.error(`Flood command ${commandIndex} failed on char ${index}:`, error.message);
                } else {
                  console.log(`Flood command ${commandIndex} (${cmd.toString('hex')}) sent to ${char.uuid}`);
                }
              });
            } catch (err) {
              console.error(`Error writing to characteristic ${char.uuid}:`, err.message);
            }
          });
          
          commandIndex++;
        }, 100); // Каждые 100мс новая команда
      }

      // Подключаемся к устройству
      if (peripheral.state === 'connected') {
        isConnected = true;
        console.log(`Device ${mac} already connected`);
        return prepareDevice();
      }

      console.log(`Connecting to ${mac}...`);
      peripheral.connect((error) => {
        if (error) {
          console.error(`Failed to connect to ${mac}:`, error);
          return res.status(500).json({ 
            error: "Connection failed", 
            message: `Failed to connect to ${mac}: ${error.message}` 
          });
        }

        isConnected = true;
        console.log(`Successfully connected to ${mac}`);
        prepareDevice();
      });
    }

    function prepareDevice() {
      // Находим все writable характеристики
      peripheral.discoverServices([], (error, services) => {
        if (error) {
          console.error('Service discovery failed:', error);
          return cleanup();
        }

        let servicesProcessed = 0;
        let allCharacteristics = [];

        services.forEach(service => {
          service.discoverCharacteristics([], (error, characteristics) => {
            if (error) {
              console.error('Characteristic discovery failed:', error);
              servicesProcessed++;
              if (servicesProcessed === services.length) {
                if (writableCharacteristics.length === 0) {
                  console.log('No writable characteristics found');
                  return cleanup();
                }
                startFlood();
              }
              return;
            }

            allCharacteristics.push(...characteristics);
            servicesProcessed++;

            if (servicesProcessed === services.length) {
              // Фильтруем writable характеристики
              writableCharacteristics = allCharacteristics.filter(char => 
                char.properties.includes('write') || char.properties.includes('writeWithoutResponse')
              );

              console.log(`Found ${writableCharacteristics.length} writable characteristics for flood:`);
              writableCharacteristics.forEach((char, index) => {
                console.log(`  ${index + 1}. ${char.uuid} - ${char.properties.join(', ')}`);
              });

              if (writableCharacteristics.length === 0) {
                console.log('No writable characteristics found');
                return cleanup();
              }

              startFlood();
            }
          });
        });
      });
    }

    function cleanup() {
      console.log(`Cleaning up flood session for ${mac}...`);
      
      if (floodInterval) {
        clearInterval(floodInterval);
        floodInterval = null;
      }

      if (isConnected && peripheral) {
        try {
          peripheral.disconnect();
          console.log(`Disconnected from ${mac}`);
        } catch (err) {
          console.error(`Error disconnecting from ${mac}:`, err.message);
        }
      }

      res.json({ 
        status: "flood_completed", 
        mac: mac,
        message: `Flood session completed for ${mac}` 
      });
    }

    // Автоматическое отключение через 10 секунд
    setTimeout(() => {
      console.log('10 seconds elapsed, stopping flood...');
      cleanup();
    }, 10000);

  } catch (error) {
    console.error(`Error during flood for ${mac}:`, error);
    res.status(500).json({ 
      error: "Flood error", 
      message: `Error during flood for ${mac}: ${error.message}` 
    });
  }
}

// Export functions and data
module.exports = {
  setupNobleEvents,
  handleDevicePreparation,
  sendVolumeCommand,
  disconnectDevice,
  floodVolumeCommands,
  connectedDevices,
  devices,
  history,
  clients,
  broadcast,
  noble
};
