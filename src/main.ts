import * as fs from 'fs';
import { simpleParser } from 'mailparser';
import { SMTPServer } from 'smtp-server';

import AliasRepository from './repositories/AliasRepository.ts';
import EncryptionService from './services/EncryptionService.ts';
import MailingService from './services/MailingService.ts';

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
        callback();
    },
    async onMailFrom(address, session, callback) {
        console.log('MAIL FROM:', address.address);
        callback();
    },
    async onRcptTo(address, session, callback) {
        console.log('RCPT TO:', address.address);
        if (!address.address.endsWith('@1337.legal')) {
            console.log('Rejecting non-1337.legal recipient:', address.address);
            return callback(new Error('Only @1337.legal addresses are allowed'));
        }

        callback();
    },
    async onData(stream, session, callback) {
        console.log('onData called');
        try {
            const parsed = await simpleParser(stream);
            const recipient = session.envelope.rcptTo?.[0]?.address;
            if (!recipient) {
                console.log('No recipient found in email');
                callback(new Error('No recipient found in email'));
                return;
            }

            const alias = await AliasRepository.findAliasByAddress(recipient);
            console.log('Alias lookup result:', alias);
            if (!alias || !alias.user) {
                console.log('No user found for recipient alias:', recipient);
                callback(new Error('No user found for recipient alias'));
                return;
            }

            const user = alias.user;

            const textContent = parsed.text || '';
            const htmlContent = parsed.html || '';

            const encryptedText = textContent ? await EncryptionService.encryptEmailContent(textContent, user.pgpPublicKey) : '';
            const encryptedHtml = htmlContent ? await EncryptionService.encryptEmailContent(htmlContent, user.pgpPublicKey) : undefined;

            const originalFrom = parsed.from?.value?.[0]?.address || 'unknown';
            const recipientDomain = getDomainFromEmail(recipient) || 'unknown.com';
            const from = `${parsed.from?.text.split(' <')[0]} <${originalFrom.replace('@', '_at_')}_${alias.address.split('@')[0]}@${recipientDomain}>`

            await MailingService.sendMail({
                from: from,
                to: user.forwardAddress,
                subject: parsed.subject || 'No Subject',
                text: encryptedText || encryptedHtml || 'No content',
                html: encryptedHtml
            });

            console.log(`${new Date().toISOString()}: ${originalFrom} -> relay ${from} -> ${user.forwardAddress} with subject: ${parsed.subject || 'No Subject'}`);
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