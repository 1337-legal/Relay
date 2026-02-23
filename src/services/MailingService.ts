import dns from 'dns/promises';
import nodemailer from 'nodemailer';

import BaseService from './BaseService.ts';
import EncryptionService from './EncryptionService.ts';

/**
 * MailingService provides email sending capabilities with DKIM signing, MX record resolution,
 * address serialization, and optional content encryption.
 * 
 * This service extends BaseService and requires the following environment variables:
 * - `DKIM_PRIVATE_KEY`: The private key for DKIM signing (as a string, with `\n` replaced by newlines).
 * - `DKIM_DOMAIN`: The domain used for DKIM signing.
 * - `DKIM_SELECTOR`: The DKIM selector.
 * 
 * Features:
 * - Resolves MX records for recipient domains to determine mail exchange hosts.
 * - Serializes sender addresses to include aliasing and display names.
 * - Optionally encrypts email content using a provided public key.
 * - Sends emails using nodemailer with DKIM signing and TLS.
 * 
 * @example
 * const service = new MailingService();
 * await service.sendMail({
 *   from: 'Alice <alice@example.com>',
 *   to: 'bob@example.org',
 *   subject: 'Hello',
 *   content: { text: 'Hi Bob!', html: '<b>Hi Bob!</b>' },
 *   publicKey: '-----BEGIN PUBLIC KEY-----...'
 * });
 */
class MailingService extends BaseService {
    public domain: string;
    public selector: string;
    public privateKey: string;

    constructor() {
        super();
        this.checkEnvironment(['DKIM_PRIVATE_KEY', 'DKIM_DOMAIN', 'DKIM_SELECTOR']);

        this.domain = process.env.DKIM_DOMAIN || 'yourdomain.com';
        this.selector = process.env.DKIM_SELECTOR || 'default';
        this.privateKey = (process.env.DKIM_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    }

    /**
     * Resolves the mail exchange (MX) server and port for a given email address.
     * 
     * @param email - The recipient's email address.
     * @returns A Promise resolving to a tuple containing the MX server hostname and port number.
     * @throws If the email address is invalid or MX records cannot be resolved.
     */
    async resolveMailExchange(email: string): Promise<[string, number]> {
        const domain = email.split('@')[1];
        if (!domain) {
            throw new Error(`Invalid email address: ${email}`);
        }
        try {
            const mxRecords = await dns.resolveMx(domain);
            if (!mxRecords || mxRecords.length === 0) {
                throw new Error(`No MX records found for domain: ${domain}`);
            }

            mxRecords.sort((a, b) => a.priority - b.priority);
            const firstRecord = mxRecords[0];
            if (!firstRecord || !firstRecord.exchange) {
                throw new Error(`Invalid MX record for domain: ${domain}`);
            }
            return [firstRecord.exchange, 25];
        } catch (err) {
            throw new Error(`Failed to resolve MX for ${domain}: ${err instanceof Error ? err.message : String(err)}`);
        }
    }

    /**
     * Extracts the domain part from an email address.
     * 
     * @param email - The email address to extract the domain from.
     * @returns A Promise resolving to the domain string, or null if extraction fails.
     */
    async getDomainFromEmail(email: string): Promise<string | null> {
        const match = email.match(/@(.+)$/);
        return match && typeof match[1] === 'string' ? match[1] : null;
    }

    /**
     * Serializes an email address for aliasing, optionally including a display name.
     * 
     * @param from - The original sender address, possibly with a display name.
     * @param alias - The alias email address to use for serialization.
     * @returns A Promise resolving to the serialized address string, or null if serialization fails.
     */
    async serializeAddress(from: string, alias: string): Promise<string | null> {
        const emailRegex = /^(?:(.+?)\s*<([^>]+)>|([^<>\s]+))$/;
        const match = from.trim().match(emailRegex);

        if (!match) return null;

        const displayName = match[1] || '';
        const originalFrom = match[2] || match[3];

        if (!originalFrom) return null;

        const recipientDomain = await this.getDomainFromEmail(alias);
        if (!recipientDomain) return null;

        const aliasLocal = alias.split('@')[0];
        const serialized = `${originalFrom.replace('@', '_at_')}_${aliasLocal}@${recipientDomain}`;

        return displayName
            ? `${displayName} <${serialized}>`
            : serialized;
    }

    /**
     * Deserializes an email address that was previously serialized for aliasing.
     *
     * @param serialized - The serialized email address to deserialize.
     * @return A Promise resolving to the original email address string, or null if deserialization fails
     */
    async deserializeAddress(serialized: string): Promise<{from: string, alias: string} | null> {
        const emailRegex = /<([^>]+)>|([^<>\s]+)$/;
        const match = serialized.trim().match(emailRegex);

        if (!match) return null;

        const emailPart = match[1] || match[2];
        if (!emailPart) return null;

        const atIndex = emailPart.lastIndexOf('@');
        if (atIndex === -1) return null;

        const localPart = emailPart.substring(0, atIndex);
        const domain = emailPart.substring(atIndex + 1);

        const lastUnderscoreIndex = localPart.lastIndexOf('_');
        if (lastUnderscoreIndex === -1) return null;

        const aliasLocal = localPart.substring(lastUnderscoreIndex + 1);
        const encodedOriginal = localPart.substring(0, lastUnderscoreIndex);

        const originalFrom = encodedOriginal.replace(/_at_/g, '@');

        const alias = `${aliasLocal}@${domain}`;

        return {
            from: originalFrom,
            alias: alias
        };
    }

    /**
     * Encrypts the provided email content using the given public key.
     * 
     * @param content - The plain text or HTML content to encrypt.
     * @param publicKey - The public key to use for encryption. If not provided, returns the original content.
     * @returns A Promise resolving to the encrypted content string.
     */
    async encryptContent(content: string, publicKey?: string): Promise<string> {
        if (!publicKey) {
            return content;
        }

        try {
            return await EncryptionService.encryptEmailContent(content, publicKey);
        } catch (error) {
            console.error('Failed to encrypt content, sending unencrypted:', error);
            return content;
        }
    }

    /**
     * Sends an email with optional DKIM signing and content encryption.
     * 
     * @param params - The mail parameters.
     * @param params.from - The sender's email address.
     * @param params.to - The recipient's email address.
     * @param params.subject - The subject of the email.
     * @param params.content - The email content, including text and/or HTML.
     * @param params.publicKey - Optional public key for encrypting the content.
     * @param params.attachments - Optional attachments to include in the email.
     * @returns A Promise resolving to the result of the email sending operation.
     * @throws If sending fails or required parameters are missing.
     */
    async sendMail({ from, to, subject, content, publicKey, attachments, replyTo, messageId, inReplyTo, references }: {
        from: string,
        to: string,
        subject: string,
        content: {
            text: string | undefined,
            html: string | false
        },
        publicKey?: string | null,
        attachments?: Array<{
            filename?: string,
            contentType?: string,
            contentDisposition?: string,
            content: Buffer,
            cid?: string
        }>,
        replyTo?: string,
        messageId?: string,
        inReplyTo?: string | string[],
        references?: string | string[]
    }) {
        const [host, port] = await this.resolveMailExchange(to);

        try {
            const transporter = nodemailer.createTransport({
                host,
                port,
                secure: false,
                requireTLS: true,
                tls: {
                    rejectUnauthorized: false,
                    ciphers: 'SSLv3'
                },
                dkim: {
                    domainName: this.domain,
                    keySelector: this.selector,
                    privateKey: this.privateKey
                }
            });

            let mailOptions: any = {
                from,
                to,
                subject
            };

            // Add email threading headers
            if (replyTo) mailOptions.replyTo = replyTo;
            if (messageId) mailOptions.messageId = messageId;
            if (inReplyTo) mailOptions.inReplyTo = inReplyTo;
            if (references) mailOptions.references = references;

            if (publicKey) {
                const multipartContent = this.createMultipartContent(content, attachments);
                const encryptedContent = await this.encryptContent(multipartContent, publicKey);

                const pgpBoundary = `----=_NextPart_${Date.now()}_${Math.random().toString(36)}`;

                mailOptions.raw = this.createPGPMimeMessage({
                    from,
                    to,
                    subject,
                    encryptedContent,
                    boundary: pgpBoundary,
                    replyTo,
                    messageId,
                    inReplyTo,
                    references
                });
            } else {
                if (content.text) {
                    mailOptions.text = content.text;
                }
                if (content.html && typeof content.html === 'string') {
                    mailOptions.html = content.html;
                }
                if (attachments && attachments.length) {
                    mailOptions.attachments = attachments.map(a => ({
                        filename: a.filename,
                        content: a.content,
                        contentType: a.contentType,
                        contentDisposition: a.contentDisposition,
                        cid: a.cid
                    }));
                }
            }

            return await transporter.sendMail(mailOptions);
        } catch (error) {
            console.error('Error sending mail:', {
                host, port, from, to, subject,
                encrypted: !!publicKey,
                dkim: {
                    domainName: this.domain,
                    keySelector: this.selector,
                    privateKey: this.privateKey ? '[REDACTED]' : '[MISSING]'
                },
                error
            });
            throw error;
        }
    }

    /**
     * Creates a proper PGP/MIME message structure for ProtonMail compatibility
     * 
     * @param params - The parameters for the PGP/MIME message.
     * @param params.from - The sender's email address.
     * @param params.to - The recipient's email address.
    */
    private createPGPMimeMessage({ from, to, subject, encryptedContent, boundary, replyTo, messageId, inReplyTo, references }: {
        from: string,
        to: string,
        subject: string,
        encryptedContent: string,
        boundary: string,
        replyTo?: string,
        messageId?: string,
        inReplyTo?: string | string[],
        references?: string | string[]
    }): string {
        const date = new Date().toUTCString();

        let message = `From: ${from}\r\n`;
        message += `To: ${to}\r\n`;
        message += `Subject: ${subject}\r\n`;
        message += `Date: ${date}\r\n`;
        if (replyTo) message += `Reply-To: ${replyTo}\r\n`;
        if (messageId) message += `Message-ID: ${messageId}\r\n`;
        if (inReplyTo) {
            const inReplyToValue = Array.isArray(inReplyTo) ? inReplyTo.join(' ') : inReplyTo;
            message += `In-Reply-To: ${inReplyToValue}\r\n`;
        }
        if (references) {
            const referencesValue = Array.isArray(references) ? references.join(' ') : references;
            message += `References: ${referencesValue}\r\n`;
        }
        message += `MIME-Version: 1.0\r\n`;
        message += `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${boundary}"\r\n\r\n`;

        // First part: PGP version indicator
        message += `--${boundary}\r\n`;
        message += `Content-Type: application/pgp-encrypted\r\n`;
        message += `Content-Description: PGP/MIME version identification\r\n\r\n`;
        message += `Version: 1\r\n\r\n`;

        // Second part: Encrypted data
        message += `--${boundary}\r\n`;
        message += `Content-Type: application/octet-stream; name="encrypted.asc"\r\n`;
        message += `Content-Description: OpenPGP encrypted message\r\n`;
        message += `Content-Disposition: inline; filename="encrypted.asc"\r\n\r\n`;
        message += `${encryptedContent}\r\n`;

        message += `--${boundary}--\r\n`;

        return message;
    }

    /**
     * Creates a multipart MIME content structure that preserves HTML after PGP decryption
     */
    private createMultipartContent(content: { text: string | undefined, html: string | false }, attachments?: Array<{
        filename?: string,
        contentType?: string,
        contentDisposition?: string,
        content: Buffer,
        cid?: string
    }>): string {
        if (!attachments || attachments.length === 0) {
            const boundary = `----=_Part_${Date.now()}_${Math.random().toString(36)}`;

            let mimeContent = `MIME-Version: 1.0\r\n`;
            mimeContent += `Content-Type: multipart/alternative; boundary="${boundary}"\r\n\r\n`;

            if (content.text) {
                mimeContent += `--${boundary}\r\n`;
                mimeContent += `Content-Type: text/plain; charset=utf-8\r\n`;
                mimeContent += `Content-Transfer-Encoding: 8bit\r\n\r\n`;
                mimeContent += `${content.text}\r\n\r\n`;
            }

            if (content.html && typeof content.html === 'string') {
                mimeContent += `--${boundary}\r\n`;
                mimeContent += `Content-Type: text/html; charset=utf-8\r\n`;
                mimeContent += `Content-Transfer-Encoding: 8bit\r\n\r\n`;
                mimeContent += `${content.html}\r\n\r\n`;
            }

            mimeContent += `--${boundary}--\r\n`;

            return mimeContent;
        }

        const mixedBoundary = `----=_Mixed_${Date.now()}_${Math.random().toString(36)}`;
        const altBoundary = `----=_Alt_${Date.now()}_${Math.random().toString(36)}`;

        let mime = `MIME-Version: 1.0\r\n`;
        mime += `Content-Type: multipart/mixed; boundary="${mixedBoundary}"\r\n\r\n`;

        mime += `--${mixedBoundary}\r\n`;
        mime += `Content-Type: multipart/alternative; boundary="${altBoundary}"\r\n\r\n`;

        if (content.text) {
            mime += `--${altBoundary}\r\n`;
            mime += `Content-Type: text/plain; charset=utf-8\r\n`;
            mime += `Content-Transfer-Encoding: 8bit\r\n\r\n`;
            mime += `${content.text}\r\n\r\n`;
        }

        if (content.html && typeof content.html === 'string') {
            mime += `--${altBoundary}\r\n`;
            mime += `Content-Type: text/html; charset=utf-8\r\n`;
            mime += `Content-Transfer-Encoding: 8bit\r\n\r\n`;
            mime += `${content.html}\r\n\r\n`;
        }

        mime += `--${altBoundary}--\r\n\r\n`;

        for (const att of attachments) {
            const filename = att.filename || 'attachment';
            const contentType = att.contentType || 'application/octet-stream';
            const disposition = (att.contentDisposition && att.contentDisposition.toLowerCase() === 'inline') ? 'inline' : 'attachment';
            const base64 = this.chunkBase64(att.content.toString('base64'));

            mime += `--${mixedBoundary}\r\n`;
            mime += `Content-Type: ${contentType}; name="${this.encodeHeaderParam(filename)}"\r\n`;
            mime += `Content-Transfer-Encoding: base64\r\n`;
            mime += `Content-Disposition: ${disposition}; filename="${this.encodeHeaderParam(filename)}"\r\n`;
            if (att.cid) {
                mime += `Content-ID: <${att.cid}>\r\n`;
            }
            mime += `\r\n${base64}\r\n\r\n`;
        }

        mime += `--${mixedBoundary}--\r\n`;
        return mime;
    }

    private chunkBase64(b64: string): string {
        return b64.replace(/.{1,76}/g, '$&\r\n').trim();
    }

    private encodeHeaderParam(value: string): string {
        return value.replace(/(["\\])/g, '\\$1');
    }
}

export default new MailingService();
