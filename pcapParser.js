const PcapParser = require('pcap-parser');

function parsePcapFile(filePath, ipAddresses, macAddresses, macToIpMap, communicationMap, addUnsafeIP, safeIPAddresses, iec104Data) {
    const parser = PcapParser.parse(filePath);
    parser.on('packet', (packet) => {
        // console.log('Packet processed');  // Debugging-Log
        if (packet.data.length > 33) {
            const ethertype = packet.data.readUInt16BE(12);
            let offset = 14;

            if (ethertype === 0x8100) {
                offset += 4;
            }

            const macSrc = packet.data.slice(6, 12).toString('hex').match(/.{1,2}/g).join(':');
            const macDst = packet.data.slice(0, 6).toString('hex').match(/.{1,2}/g).join(':');
            macAddresses.add(macSrc);
            macAddresses.add(macDst);

            if (packet.data.readUInt16BE(12 + (offset - 14)) === 0x0800) {
                const ipHeaderLength = (packet.data[offset] & 0x0F) * 4;
                const protocol = packet.data[offset + 9];

                const ipSrc = packet.data.slice(offset + 12, offset + 16).join('.');
                const ipDst = packet.data.slice(offset + 16, offset + 20).join('.');

                if (!safeIPAddresses.has(ipSrc)) {
                    ipAddresses.add(ipSrc);
                    addUnsafeIP(ipSrc);
                }
                if (!safeIPAddresses.has(ipDst)) {
                    ipAddresses.add(ipDst);
                    addUnsafeIP(ipDst);
                }

                mapMacToIp(macToIpMap, macSrc, ipSrc);
                mapMacToIp(macToIpMap, macDst, ipDst);

                if (protocol === 6 || protocol === 17) {
                    const srcPort = packet.data.readUInt16BE(offset + ipHeaderLength);
                    const dstPort = packet.data.readUInt16BE(offset + ipHeaderLength + 2);
                    trackCommunication(communicationMap, macSrc, ipSrc, macDst, ipDst, srcPort, dstPort);
                    // console.log(`MAC Src: ${macSrc}, MAC Dst: ${macDst}, IP Src: ${ipSrc}, IP Dst: ${ipDst}, Src Port: ${srcPort}, Dst Port: ${dstPort}`);

                    // IEC104 spezifische Daten extrahieren
                    if (srcPort === 2404 || dstPort === 2404) {
                        const tcpHeaderLength = ((packet.data[offset + ipHeaderLength + 12] & 0xF0) >> 4) * 4;
                        const iec104Offset = offset + ipHeaderLength + tcpHeaderLength;
                        const iec104PacketData = packet.data.slice(iec104Offset);
                        parseIEC104Data(iec104PacketData, ipSrc, ipDst, srcPort, dstPort, iec104Data, packet.header.timestampSeconds, packet.header.timestampMicroseconds);
                    }
                }
            }
        }
    });

    parser.on('end', () => {
        // console.log('Parsing finished. Total IPs:', ipAddresses.size)
    });
    parser.on('error', (error) => {
        // console.error('Error while parsing the pcap file:', error)
    });
}

function mapMacToIp(macToIpMap, mac, ip) {
    if (!macToIpMap[mac]) {
        macToIpMap[mac] = new Set();
    }
    macToIpMap[mac].add(ip);
}

function trackCommunication(communicationMap, macSrc, ipSrc, macDst, ipDst, srcPort, dstPort) {
    const key = `${macSrc}>${macDst}`;

    if (!communicationMap.has(key)) {
        communicationMap.set(key, []);
    }

    let communications = communicationMap.get(key);
    let existingCommunication = communications.find(comm => comm.ipSrc === ipSrc && comm.ipDst === ipDst && comm.srcPort === srcPort && comm.dstPort === dstPort);

    if (!existingCommunication) {
        communications.push({ macSrc, ipSrc, macDst, ipDst, srcPort, dstPort });
    }
}

function parseIEC104Data(data, ipSrc, ipDst, srcPort, dstPort, iec104DataArray, packetTimestampSeconds, packetTimestampMicroseconds) {
    if (data.length < 2) return;  // Mindestlänge für IEC104-Paket

    const startByte = data[0];
    const length = data[1];

    if (startByte !== 0x68) return;  // Ungültiges IEC104-Paket

    const apduType = data[2] & 0x03;
    let apduTypeStr;
    let detailedInfo = {};

    switch (apduType) {
        case 0:
            apduTypeStr = 'I-Format';
            detailedInfo = parseIFormat(data);
            break;
        case 1:
            apduTypeStr = 'S-Format';
            detailedInfo = parseSFormat(data);
            break;
        case 3:
            apduTypeStr = 'U-Format';
            detailedInfo = parseUFormat(data);
            break;
        default:
            apduTypeStr = 'Unbekannt';
    }

    // Use the timestamp from IEC104 data if available, otherwise use packet timestamp
    const packetTimestamp = new Date((packetTimestampSeconds * 1000) + (packetTimestampMicroseconds / 1000));
    const timestamp = detailedInfo.timestamp || packetTimestamp;

    // console.log('Parsed timestamp:', timestamp);  // Debug output

    const iec104Entry = {
        timestamp: timestamp.toISOString(),
        ipSrc,
        ipDst,
        srcPort,
        dstPort,
        apduType: apduTypeStr,
        length: length,
        ...detailedInfo,
        rawData: data.toString('hex')
    };

    iec104DataArray.push(iec104Entry);
}

function parseIFormat(data) {
    const sendSeq = (data[2] << 8 | data[3]) >> 1;
    const receiveSeq = (data[4] << 8 | data[5]) >> 1;
    
    let asduType = data[6];
    let numIx = data[7];
    let cot = data[8] | (data[9] << 8);
    let asduAddr = data[10] | (data[11] << 8);
    let ioAddr = data[12] | (data[13] << 8) | (data[14] << 16);
    
    const infoObj = parseInfoObject(data.slice(15), asduType);
    
    return {
        sendSeq,
        receiveSeq,
        asduType: getAsduTypeString(asduType),
        numIx,
        cot: getCauseOfTransmissionString(cot),
        asduAddr,
        ioAddr,
        infoObj,
        timestamp: infoObj.timestamp
    };
}

function parseSFormat(data) {
    const receiveSeq = (data[4] << 8 | data[5]) >> 1;
    return { receiveSeq };
}

function parseUFormat(data) {
    const controlField = data[2];
    let uType = '';
    if (controlField & 0x04) uType = 'STARTDT';
    else if (controlField & 0x08) uType = 'STOPDT';
    else if (controlField & 0x10) uType = 'TESTFR';
    return { uType };
}

function getAsduTypeString(type) {
    const asduTypes = {
        1: 'M_SP_NA_1', 3: 'M_DP_NA_1', 5: 'M_ST_NA_1', 7: 'M_BO_NA_1',
        9: 'M_ME_NA_1', 11: 'M_ME_NB_1', 13: 'M_ME_NC_1', 15: 'M_IT_NA_1',
        20: 'M_PS_NA_1', 21: 'M_ME_ND_1', 30: 'M_SP_TB_1', 31: 'M_DP_TB_1',
        32: 'M_ST_TB_1', 33: 'M_BO_TB_1', 34: 'M_ME_TD_1', 35: 'M_ME_TE_1',
        36: 'M_ME_TF_1', 37: 'M_IT_TB_1', 38: 'M_EP_TD_1', 39: 'M_EP_TE_1',
        40: 'M_EP_TF_1', 45: 'C_SC_NA_1', 46: 'C_DC_NA_1', 47: 'C_RC_NA_1',
        48: 'C_SE_NA_1', 49: 'C_SE_NB_1', 50: 'C_SE_NC_1', 51: 'C_BO_NA_1',
        58: 'C_SC_TA_1', 59: 'C_DC_TA_1', 60: 'C_RC_TA_1', 61: 'C_SE_TA_1',
        62: 'C_SE_TB_1', 63: 'C_SE_TC_1', 64: 'C_BO_TA_1', 70: 'M_EI_NA_1',
        100: 'C_IC_NA_1', 101: 'C_CI_NA_1', 102: 'C_RD_NA_1', 103: 'C_CS_NA_1',
        104: 'C_TS_NA_1', 105: 'C_RP_NA_1', 106: 'C_CD_NA_1', 107: 'C_TS_TA_1',
        110: 'P_ME_NA_1', 111: 'P_ME_NB_1', 112: 'P_ME_NC_1', 113: 'P_AC_NA_1',
        120: 'F_FR_NA_1', 121: 'F_SR_NA_1', 122: 'F_SC_NA_1', 123: 'F_LS_NA_1',
        124: 'F_AF_NA_1', 125: 'F_SG_NA_1', 126: 'F_DR_TA_1', 127: 'F_SC_NB_1'
    };
    return asduTypes[type] || `Unknown (${type})`;
}

function getCauseOfTransmissionString(cot) {
    const causes = {
        1: 'Periodic', 2: 'Background scan', 3: 'Spontaneous',
        4: 'Initialized', 5: 'Request or requested',
        6: 'Activation', 7: 'Activation confirmation',
        8: 'Deactivation', 9: 'Deactivation confirmation',
        10: 'Activation termination', 11: 'Return information caused by a remote command',
        12: 'Return information caused by a local command',
        13: 'File transfer', 20: 'Interrogated by station interrogation',
        21: 'Interrogated by group 1 interrogation',
        22: 'Interrogated by group 2 interrogation',
        23: 'Interrogated by group 3 interrogation',
        24: 'Interrogated by group 4 interrogation',
        25: 'Interrogated by group 5 interrogation',
        26: 'Interrogated by group 6 interrogation',
        27: 'Interrogated by group 7 interrogation',
        28: 'Interrogated by group 8 interrogation',
        29: 'Interrogated by group 9 interrogation',
        30: 'Interrogated by group 10 interrogation',
        31: 'Interrogated by group 11 interrogation',
        32: 'Interrogated by group 12 interrogation',
        33: 'Interrogated by group 13 interrogation',
        34: 'Interrogated by group 14 interrogation',
        35: 'Interrogated by group 15 interrogation',
        36: 'Interrogated by group 16 interrogation',
        37: 'Requested by general counter request',
        38: 'Requested by group 1 counter request',
        39: 'Requested by group 2 counter request',
        40: 'Requested by group 3 counter request',
        41: 'Requested by group 4 counter request',
        44: 'Unknown type identification',
        45: 'Unknown cause of transmission',
        46: 'Unknown common address of ASDU',
        47: 'Unknown information object address'
    };
    return causes[cot] || `Unknown (${cot})`;
}

function parseInfoObject(data, asduType) {
    switch (asduType) {
        case 1: // M_SP_NA_1 - Single-point information
        case 3: // M_DP_NA_1 - Double-point information
            return { value: data[0] & 0x01 };
        case 5: // M_ST_NA_1 - Step position information
            return { value: data.readInt8(0) };
        case 7: // M_BO_NA_1 - Bitstring of 32 bits
            return { value: data.readUInt32LE(0) };
        case 9: // M_ME_NA_1 - Measured value, normalized value
        case 11: // M_ME_NB_1 - Measured value, scaled value
            return { value: data.readInt16LE(0) };
        case 13: // M_ME_NC_1 - Measured value, short floating point number
            return { value: data.readFloatLE(0) };
        case 15: // M_IT_NA_1 - Integrated totals
            return { value: data.readInt32LE(0) };
        case 20: // M_PS_NA_1 - Packed single-point information with status change detection
            return { value: data.readUInt32LE(0) };
        case 21: // M_ME_ND_1 - Measured value, normalized value without quality descriptor
            return { value: data.readInt16LE(0) };
        case 30: // M_SP_TB_1 - Single-point information with time tag CP56Time2a
        case 31: // M_DP_TB_1 - Double-point information with time tag CP56Time2a
            return {
                value: data[0] & 0x01,
                timestamp: parseCP56Time2a(data.slice(1))
            };
        case 32: // M_ST_TB_1 - Step position information with time tag CP56Time2a
            return {
                value: data.readInt8(0),
                timestamp: parseCP56Time2a(data.slice(1))
            };
        case 33: // M_BO_TB_1 - Bitstring of 32 bit with time tag CP56Time2a
            return {
                value: data.readUInt32LE(0),
                timestamp: parseCP56Time2a(data.slice(4))
            };
        case 34: // M_ME_TD_1 - Measured value, normalized value with time tag CP56Time2a
        case 35: // M_ME_TE_1 - Measured value, scaled value with time tag CP56Time2a
            return {
                value: data.readInt16LE(0),
                timestamp: parseCP56Time2a(data.slice(2))
            };
        case 36: // M_ME_TF_1 - Measured value, short floating point number with time tag CP56Time2a
            return {
                value: data.readFloatLE(0),
                timestamp: parseCP56Time2a(data.slice(4))
            };
        case 37: // M_IT_TB_1 - Integrated totals with time tag CP56Time2a
            return {
                value: data.readInt32LE(0),
                timestamp: parseCP56Time2a(data.slice(4))
            };
        // Add more cases for other ASDU types as needed
        default:
            return { value: 'Not implemented', asduType: asduType };
    }
}

function parseCP56Time2a(data, offset = 0) {
    // Hex-Dump Ausgabe
    // console.log('Hex-Dump des Zeitstempels:');
    // for (let i = 0; i < 7; i++) {
    //     console.log(`Byte ${i}: ${data[offset + i].toString(16).padStart(2, '0')}`);
    // }

    const totalMilliseconds = data.readUInt16LE(offset);
    const second = Math.floor(totalMilliseconds / 1000) % 60;
    const millisecond = totalMilliseconds % 1000;
    const minute = data[offset + 2] & 0x3F;
    const hour = data[offset + 3] & 0x1F;
    const dayOfMonth = data[offset + 4] & 0x1F;
    
    // Korrigierte Monatsberechnung
    const month = data[offset + 5] - 1;  // JavaScript Monate sind 0-basiert

    const yearValue = data[offset + 6] & 0x7F;
    //console.log('Raw yearValue:', yearValue);

    const fullYear = 2014 + yearValue;
    // console.log('Adjusted fullYear:', fullYear);
    
    // Debugging-Ausgabe
    /* console.log('Gesamtmillisekunden:', totalMilliseconds);
    console.log('Sekunde:', second);
    console.log('Millisekunde:', millisecond);
    console.log('Minute:', minute);
    console.log('Stunde:', hour);
    console.log('Tag:', dayOfMonth);
    console.log('Monat:', month + 1);  // +1 für die Anzeige, da JavaScript-Monate 0-basiert sind
    console.log('Jahr:', fullYear);
     */
    if (minute > 59 || hour > 23 || dayOfMonth < 1 || dayOfMonth > 31 || month < 0 || month > 11) {
        // console.error('Ungültige Zeit- oder Datumsangaben');
        return null;
    }
    
    const timestamp = new Date(Date.UTC(fullYear, month, dayOfMonth, hour, minute, second, millisecond));
    // console.log('CP56Time2a parsed:', timestamp);
    
    return timestamp;
}

module.exports = { parsePcapFile };