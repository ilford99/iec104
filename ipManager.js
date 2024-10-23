const fs = require('fs');
const csvParse = require('csv-parse/lib/sync');
const config = require('./config');

function readSafeIPsFromCSV() {
    try {
        const csvData = fs.readFileSync(config.safeIPFilePath, 'utf-8');
        const records = csvParse(csvData, {
            columns: headers => headers.map(h => h.trim()),
            delimiter: ';',
            skip_empty_lines: true
        });
        return new Map(records.map(record => [record.IP, record.Name]));
    } catch (error) {
        console.error('Fehler beim Lesen der CSV-Datei für sichere IPs:', error);
        return new Map();
    }
}

function readUnsafeIPs() {
    try {
        const data = fs.readFileSync(config.unsafeIPFilePath, 'utf-8');
        const records = csvParse(data, {
            columns: true,
            skip_empty_lines: true
        });
        return new Map(records.map(record => [record.IP, record.Date]));
    } catch (error) {
        console.error('Fehler beim Lesen der unsicheren IP-Datei:', error);
        return new Map();
    }
}

function formatTimestamp() {
    return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

function addUnsafeIP(unsafeIPs, ip) {
    if (!unsafeIPs.has(ip)) {
        const timestamp = formatTimestamp();
        unsafeIPs.set(ip, timestamp);
        saveUnsafeIPs(unsafeIPs);
    }
}

function saveUnsafeIPs(unsafeIPs) {
    const header = 'IP,Date\n';
    const data = Array.from(unsafeIPs).map(([ip, date]) => `${ip},${date}`).join('\n');
    fs.writeFileSync(config.unsafeIPFilePath, header + data, 'utf-8');
}

module.exports = {
    readSafeIPsFromCSV,
    readUnsafeIPs,
    addUnsafeIP
};