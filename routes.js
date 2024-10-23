const express = require('express');
const router = express.Router();

function setupRoutes(ipAddresses, macAddresses, macToIpMap, safeIPAddresses, communicationMap, safeMacAddresses, iec104Data) {
    router.get('/get-ip-addresses', (req, res) => res.json(Array.from(ipAddresses)));
    
    router.get('/get-mac-addresses', (req, res) => res.json(Array.from(macAddresses)));
    
    router.get('/get-mac-ip-mappings', (req, res) => {
        res.json(Object.fromEntries(
            Object.keys(macToIpMap).map(mac => [mac, Array.from(macToIpMap[mac])])
        ));
    });

    router.get('/get-safe-ip-addresses', (req, res) => {
        res.json(Array.from(safeIPAddresses.entries()).map(([ip, name]) => ({ ip, name })));
    });

    router.get('/get-communications', (req, res) => {
        const results = [];
        communicationMap.forEach((communications, key) => {
            let [macSrc, macDst] = key.split('>');
            results.push({ macSrc, macDst, communications });
        });
        res.json(results);
    });

    router.get('/get-port-info', (req, res) => {
        const results = [];
        communicationMap.forEach((communications, key) => {
            let [macSrc, macDst] = key.split('>');
            communications.forEach(comm => {
                results.push({
                    macSrc,
                    macDst,
                    ipSrc: comm.ipSrc,
                    ipDst: comm.ipDst,
                    srcPort: comm.srcPort,
                    dstPort: comm.dstPort
                });
            });
        });
        res.json(results);
    });

    router.post('/add-mac', (req, res) => {
        const { mac } = req.body;
        if (safeMacAddresses.has(mac)) {
            res.status(409).send('MAC already marked as safe');
        } else {
            safeMacAddresses.add(mac);
            res.send(`MAC ${mac} added as safe`);
        }
    });

    // Neue Route für IEC104-Daten
    router.get('/get-iec104-data', (req, res) => {
        res.json(iec104Data);
    });

    return router;
}

module.exports = setupRoutes;