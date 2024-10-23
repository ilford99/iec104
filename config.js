module.exports = {
    port: 3008,
    pcapDir: 'Z:\\NPM\\pcap',
    pcapPattern: 'Z:\\NPM\\pcap\\*.pcap',
    unsafeIPFilePath: 'unsafe_ips.csv',
    safeIPFilePath: 'ip_names.csv',
    smtp: {
        host: 'smtp.example.com',
        port: 25,
        secure: false,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        },
        tls: {
            rejectUnauthorized: true
        }
    },
    emailOptions: {
        from: 'your-email@example.com',
        to: 'recipient-email@example.com',
        subject: 'Änderung an unsafe_ips.csv'
    }
};