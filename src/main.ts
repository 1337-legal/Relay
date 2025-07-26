import * as fs from 'fs';
import { simpleParser } from 'mailparser';
import { SMTPServer } from 'smtp-server';
import * as stream from 'stream';

import AliasRepository from './repositories/AliasRepository';
import EncryptionService from './services/EncryptionService';
import MailingService from './services/MailingService';

function getDomainFromEmail(email: string): string | null {
    const match = email.match(/@(.+)$/);
    return match && typeof match[1] === 'string' ? match[1] : null;
}

const server = new SMTPServer({
    name: 'mail.1337.legal',
    secure: false, // Use STARTTLS (opportunistic TLS)
    key: fs.readFileSync('/app/certificates/privkey.pem'),
    cert: fs.readFileSync('/app/certificates/fullchain.pem'),
    authOptional: true,
    async onConnect(session, callback) {
        console.log('SMTP connection from:', session.remoteAddress);
        console.log('Session details:', session);
        callback();
    },
    async onMailFrom(address, session, callback) {
        console.log('MAIL FROM:', address.address);
        callback();
    },
    async onRcptTo(address, session, callback) {
        console.log('RCPT TO:', address.address);
        callback();
    },
    async onData(stream, session, callback) {
        console.log('onData called');
        try {
            const parsed: any = await simpleParser(stream);
            console.log('Session ID:', session);
            console.log('Email parsed:', parsed);
            console.log('parsed.to:', parsed.to);
            const recipient = session.envelope.rcptTo?.[0]?.address;
            if (!recipient) {
                console.log('No recipient found in email');
                callback(new Error('No recipient found in email'));
                return;
            }

            console.log('Recipient address:', recipient);

            const alias = await AliasRepository.findAliasByAddress(recipient);
            console.log('Alias lookup result:', alias);
            if (!alias || !alias.user) {
                console.log('No user found for recipient alias:', recipient);
                callback(new Error('No user found for recipient alias'));
                return;
            }

            const user = alias.user;

            const emailContent = `Subject: ${parsed.subject}\nFrom: ${parsed.from?.text}\nTo: ${parsed.to?.text}\n\n${parsed.text}`;
            const encrypted = await EncryptionService.encryptEmailContent(emailContent, user.pgpPublicKey);

            const smtpHost = getDomainFromEmail(user.forwardAddress) || 'localhost';

            const originalFrom = parsed.from?.value?.[0]?.address || 'unknown';
            const recipientDomain = getDomainFromEmail(recipient) || 'unknown.com';
            const formattedFrom = `${originalFrom.replace('@', '_at_')}_${recipientDomain}`;

            await MailingService.sendMail({
                host: smtpHost,
                port: 587,
                from: formattedFrom,
                to: user.forwardAddress,
                subject: `[FORWARDED] ${parsed.subject}`,
                text: encrypted
            });

            console.log('Forwarded encrypted email:', parsed.subject);
            callback();
        } catch (err) {
            console.error('Error parsing or forwarding email:', err);
            callback(err as Error);
        }
    },
});

server.listen(25, () => {
    console.log('SMTP server with STARTTLS listening on port 25');
});