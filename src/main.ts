import {simpleParser} from 'mailparser';
import {SMTPServer} from 'smtp-server';

import Log from './lib/Logs.ts';
import AliasRepository from './repositories/AliasRepository.ts';
import MailingService from './services/MailingService.ts';

const reject = (callback: (err?: Error) => void, message: string) => {
    Log.Warning(message)
    callback(new Error(message))
};

const server = new SMTPServer({
    name: 'mail.1337.legal',
    secure: false,
    cert: process.env.RELAY_CERTIFICATES,
    key: process.env.RELAY_PRIVATE_KEY,
    authOptional: true,
    onRcptTo: (address, _, callback) => {
        if (address.address.endsWith('@1337.legal')) {
            callback();
        } else {
            reject(callback, 'Only @1337.legal addresses are allowed');
        }
    },
    async onData(stream, session, callback) {
        const start = Date.now();

        try {
            const mail = await simpleParser(stream);

            const recipient = session.envelope.rcptTo?.[0]?.address;
            if (!recipient) return reject(callback, 'No recipient found in email');

            const sender = mail.from?.text;
            if (!sender) return reject(callback, 'No valid sender address found in email');

            const isReply = recipient?.includes("_at_");

            if (isReply) {
                const deserialized = await MailingService.deserializeAddress(recipient);
                if (!deserialized) return reject(callback, 'Failed to deserialize reply address');

                let { from: originalRecipient, alias: aliasAddress } = deserialized;

                aliasAddress = aliasAddress.toLowerCase();

                console.log(`Reply from ${sender} via ${aliasAddress} to ${originalRecipient}`);

                const user = await AliasRepository.getUserByAlias(aliasAddress);
                if (!user) return reject(callback, `No user found for alias: ${aliasAddress}`);

                const aliasRecord = await AliasRepository.getAliasByAddress(aliasAddress);
                if (!aliasRecord || aliasRecord.status !== 'active') {
                    return reject(callback, `Alias not active: ${aliasAddress}`);
                }

                // Build references chain for proper threading
                let referencesChain: string[] = [];
                if (mail.references) {
                    referencesChain = Array.isArray(mail.references) ? mail.references : [mail.references];
                }
                // Add the In-Reply-To to the references if not already present
                if (mail.inReplyTo) {
                    const inReplyToStr = Array.isArray(mail.inReplyTo) ? mail.inReplyTo[0] : mail.inReplyTo;
                    if (inReplyToStr && !referencesChain.includes(inReplyToStr)) {
                        referencesChain.push(inReplyToStr);
                    }
                }

                const response = await MailingService.sendMail({
                    from: aliasAddress,
                    to: originalRecipient,
                    subject: mail.subject || 'No Subject',
                    content: { text: mail.text, html: mail.html },
                    replyTo: aliasAddress,
                    inReplyTo: mail.inReplyTo, // Preserve what the user replied to
                    references: referencesChain.length > 0 ? referencesChain.join(' ') : undefined,
                    attachments: mail.attachments?.map(({filename, contentType, contentDisposition, content, cid}) => ({
                        filename, contentType, contentDisposition, content: content as Buffer, cid
                    })) || []
                });

                if (!response.accepted.length) {
                    return reject(callback, `Failed to send reply to: ${originalRecipient}`);
                }

                Log.Success(`[${Date.now() - start}ms] [REDACTED] -> relay ${aliasAddress} -> ${originalRecipient}`);
                callback();
            } else {
                console.log(`Incoming email from ${sender} to ${recipient}`);

                const user = await AliasRepository.getUserByAlias(recipient);
                if (!user) return reject(callback, `No user found for recipient alias: ${recipient}`);

                const aliasRecord = await AliasRepository.getAliasByAddress(recipient);
                if (!aliasRecord || aliasRecord.status !== 'active') {
                    return reject(callback, `No alias found for recipient address: ${recipient}`);
                }

                const serializedAddress = await MailingService.serializeAddress(sender, recipient);
                if (!serializedAddress) return reject(callback, 'Failed to serialize address for forwarding');

                // Build references chain: include original references + original messageId
                let referencesChain: string[] = [];
                if (mail.references) {
                    referencesChain = Array.isArray(mail.references) ? mail.references : [mail.references];
                }
                if (mail.messageId && !referencesChain.includes(mail.messageId)) {
                    referencesChain.push(mail.messageId);
                }

                const response = await MailingService.sendMail({
                    from: serializedAddress,
                    to: user.address,
                    subject: mail.subject || 'No Subject',
                    content: { text: mail.text, html: mail.html },
                    publicKey: user.pgpPublicKey,
                    inReplyTo: mail.messageId, // User's reply should reference the original message
                    references: referencesChain.length > 0 ? referencesChain.join(' ') : undefined,
                    attachments: mail.attachments?.map(({filename, contentType, contentDisposition, content, cid}) => ({
                        filename, contentType, contentDisposition, content: content as Buffer, cid
                    })) || []
                });

                if (!response.accepted.length) {
                    return reject(callback, `Failed to send email to user forward address: ${user.address}`);
                }

                Log.Success(`[${Date.now() - start}ms] ${sender} -> relay ${serializedAddress} -> [REDACTED]`);
                callback();
            }
        } catch (err) {
            Log.Error(`Error parsing or forwarding email: ${err}`);
            callback(err as Error);
        }
    }
});

server.on('error', err => Log.Error(`SMTP server error: ${err}`));
server.listen(25, () => Log.Success('SMTP server with STARTTLS listening on port 25'));