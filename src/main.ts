import * as fs from 'fs';
import {simpleParser} from 'mailparser';
import {SMTPServer} from 'smtp-server';

import AliasRepository from '@Repositories/AliasRepository.ts';
import MailingService from '@Services/MailingService.ts';

const server = new SMTPServer({
    name: 'mail.1337.legal',
    secure: false,
    key: fs.readFileSync('/app/certificates/privkey.pem'),
    cert: fs.readFileSync('/app/certificates/fullchain.pem'),
    authOptional: true,
    async onConnect(session, callback) {
        console.log('SMTP connection from:', session.remoteAddress);
        callback();
    },
    async onMailFrom(address, session, callback) {
        console.log('MAIL FROM:', address.address);
        callback();
    },
    async onRcptTo(address, session, callback) {
        console.log('RCPT TO:', address.address);
        if (!address.address.endsWith('@1337.legal')) {
            return callback(new Error('Only @1337.legal addresses are allowed'));
        }

        callback();
    },
    async onData(stream, session, callback) {
        try {
            const dateStart = Date.now();

            const mail = await simpleParser(stream);

            const recipient = session.envelope.rcptTo?.[0]?.address;
            if (!recipient) {
                console.log('No recipient found in email');
                return callback(new Error('No recipient found in email'));
            }

            const alias = await AliasRepository.getAliasByAddress(recipient);
            if (!alias) {
                console.log('No user found for recipient alias:', recipient);
                return callback(new Error('No user found for recipient alias'));
            }

            const user = {
                address: alias.userAddress,
                pgpPublicKey: alias.pgpPublicKey
            };
            if (!mail.from || !mail.from.text) {
                console.log('No valid sender address found in email');
                return callback(new Error('No valid sender address found in email'));
            }

            const serializedAddress = await MailingService.serializeAddress(mail.from.text, alias.aliasAddress);
            if (!serializedAddress) {
                console.log('Failed to serialize address for forwarding');
                return callback(new Error('Failed to serialize address for forwarding'));
            }

            const response = await MailingService.sendMail({
                from: serializedAddress,
                to: user.address,
                subject: mail.subject || 'No Subject',
                content: {
                    text: mail.text,
                    html: mail.html
                },
                publicKey: user.pgpPublicKey,
                attachments: (mail.attachments || []).map(att => ({
                    filename: att.filename,
                    contentType: att.contentType,
                    contentDisposition: att.contentDisposition,
                    content: att.content as Buffer,
                    cid: att.cid
                }))
            });

            if (response.accepted.length === 0) {
                console.error('Failed to send email to user forward address:', user.address);
                return callback(new Error('Failed to send email to user forward address'));
            }

            console.log(`✅ [${Date.now() - dateStart}ms}] ${mail.from.text} -> relay ${serializedAddress} -> [REDACTED].`);

            callback();
        } catch (err) {
            console.error('Error parsing or forwarding email:', err);
            callback(err as Error);
        }
    }
});

server.on('error', (err) => {
    console.error('SMTP server error:', err);
});

server.listen(25, () => {
    console.log('SMTP server with STARTTLS listening on port 25');
});