const express = require('express');
const chokidar = require('chokidar');
const path = require('path');
const config = require('./config');
const { parsePcapFile } = require('./pcapParser');
const { readSafeIPsFromCSV, readUnsafeIPs, addUnsafeIP } = require('./ipManager');
const { sendEmailWithFileContents } = require('./emailService');
const setupRoutes = require('./routes');
const fs = require('fs');

const app = express();
const PORT = config.port;

// Middleware zur Überprüfung der IP-Adresse
app.use((req, res, next) => {
  const clientIp = req.connection.remoteAddress;
  if (clientIp === '127.0.0.1' || clientIp === '::1') {
    next();
  } else {
    res.status(403).send('Access denied');
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const ipAddresses = new Set();
const macAddresses = new Set();
const safeMacAddresses = new Set(['00:1B:44:11:3A:B7', '00:1B:44:11:3A:B8']);
const macToIpMap = {};
let safeIPAddresses = readSafeIPsFromCSV();
const unsafeIPs = readUnsafeIPs();
const communicationMap = new Map();
const iec104Data = []; // Neue Datenstruktur für IEC104-Daten

function refreshSafeIPAddresses() {
    safeIPAddresses = readSafeIPsFromCSV();
}

function isPcapFile(filePath) {
    const fileName = path.basename(filePath);
    return fileName.startsWith('fink_') && fileName.endsWith('.pcap');
}

function setupPcapWatcher() {
    console.log(`Setting up watcher for directory: ${config.pcapDir}`);

    // Check if the directory exists
    if (!fs.existsSync(config.pcapDir)) {
        console.error(`Directory does not exist: ${config.pcapDir}`);
        return;
    }

    const watcher = chokidar.watch(config.pcapPattern, { 
        persistent: true,
        ignoreInitial: false,
        awaitWriteFinish: {
            stabilityThreshold: 2000,
            pollInterval: 100
        }
    });

    watcher
        .on('add', filePath => {
            console.log(`File detected: ${filePath}`);
            if (isPcapFile(filePath)) {
                console.log(`New PCAP file detected: ${filePath}`);
                parsePcapFile(filePath, ipAddresses, macAddresses, macToIpMap, communicationMap, 
                              (ip) => addUnsafeIP(unsafeIPs, ip), safeIPAddresses, iec104Data);
                refreshSafeIPAddresses();
            } else {
                console.log(`File is not a valid PCAP file: ${filePath}`);
            }
        })
        .on('change', filePath => {
            console.log(`File changed: ${filePath}`);
            if (isPcapFile(filePath)) {
                console.log(`PCAP file changed: ${filePath}`);
                parsePcapFile(filePath, ipAddresses, macAddresses, macToIpMap, communicationMap, 
                              (ip) => addUnsafeIP(unsafeIPs, ip), safeIPAddresses, iec104Data);
                refreshSafeIPAddresses();
            } else {
                console.log(`Changed file is not a valid PCAP file: ${filePath}`);
            }
        })
        .on('error', error => console.error('Watcher error:', error))
        .on('ready', () => {
            console.log('Initial scan complete. Watching for new or changed PCAP files...');
            const watchedPaths = watcher.getWatched();
            console.log('Watched paths:', watchedPaths);
        });
}

// Setup routes
app.use('/', setupRoutes(ipAddresses, macAddresses, macToIpMap, safeIPAddresses, communicationMap, safeMacAddresses, iec104Data));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  setupPcapWatcher();
});
