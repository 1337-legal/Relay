import {simpleParser} from 'mailparser';
import {SMTPServer} from 'smtp-server';

import Log from './lib/Logs.ts';
import AliasRepository from '@Repositories/AliasRepository.ts';
import MailingService from '@Services/MailingService.ts';

function rejectWithError(callback: (err?: Error) => void, message: string): void {
    Log.Warning(message);
    callback(new Error(message));
}

const server = new SMTPServer({
    name: 'mail.1337.legal',
    secure: false,
    cert: process.env.RELAY_CERTIFICATES,
    key: process.env.RELAY_PRIVATE_KEY,
    authOptional: true,

    onConnect(session, callback) {
        Log.Info(`SMTP connection from ${session.remoteAddress} (${session.clientHostname})`);
        callback();
    },

    onRcptTo(address, session, callback) {
        if (!address.address.endsWith('@1337.legal')) {
            return rejectWithError(callback, 'Only @1337.legal addresses are allowed');
        }
        callback();
    },

    async onData(stream, session, callback) {
        const dateStart = Date.now();

        try {
            const mail = await simpleParser(stream);
            const recipient = session.envelope.rcptTo?.[0]?.address;
            const senderAddress = mail.from?.text;

            if (!recipient) {
                return rejectWithError(callback, 'No recipient found in email');
            }

            if (!senderAddress) {
                return rejectWithError(callback, 'No valid sender address found in email');
            }

            const user = await AliasRepository.getUserByAlias(recipient);
            if (!user) {
                return rejectWithError(callback, `No user found for recipient alias: ${recipient}`);
            }

            const serializedAddress = await MailingService.serializeAddress(senderAddress, recipient);
            if (!serializedAddress) {
                return rejectWithError(callback, 'Failed to serialize address for forwarding');
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
                return rejectWithError(callback, `Failed to send email to user forward address: ${user.address}`);
            }

            Log.Success(`[${Date.now() - dateStart}ms] ${senderAddress} -> relay ${serializedAddress} -> [REDACTED]`);
            callback();
        } catch (err) {
            Log.Error(`Error parsing or forwarding email: ${err}`);
            callback(err as Error);
        }
    }
});

server.on('error', (err) => {
    Log.Error(`SMTP server error: ${err}`);
});

server.listen(25, () => {
    Log.Success('SMTP server with STARTTLS listening on port 25');
});