const nodemailer = require('nodemailer');
const fs = require('fs');
const config = require('./config');

const transporter = nodemailer.createTransport(config.smtp);

function sendEmailWithFileContents() {
    console.log("Attempting to send email...");
    fs.readFile(config.unsafeIPFilePath, (err, data) => {
        if (err) {
            console.error('Error reading the unsafe IP file:', err);
            return;
        }
        const mailOptions = {
            ...config.emailOptions,
            text: 'Es gibt eine Änderung bei den unsicheren IPs. Siehe Anhang.',
            attachments: [{
                filename: 'unsafe_ips.csv',
                content: data
            }]
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
            } else {
                console.log('Email successfully sent:', info.response);
            }
        });
    });
}

module.exports = { sendEmailWithFileContents };