import dns from 'dns/promises';
import nodemailer from 'nodemailer';

import BaseService from './BaseService.ts';

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

    async solveMailExchange(email: string): Promise<[string, number]> {
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

    async sendMail({ from, to, subject, text, html }: {
        from: string,
        to: string,
        subject: string,
        text: string,
        html?: string,
    }) {
        const [host, port] = await this.solveMailExchange(to);

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

            const headers: Record<string, string> = {}
            if (html) {
                headers['Content-Type'] = 'text/html; charset=utf-8';
            } else {
                headers['Content-Type'] = 'text/plain; charset=utf-8';
            }

            const info = await transporter.sendMail({
                from,
                to,
                subject,
                text,
                html,
                headers
            });

            console.log('Mail sent:', info);
            return info;
        } catch (error) {
            console.error('Error sending mail:', {
                host, port, from, to, subject, text, html: html ? '[HTML_CONTENT]' : undefined,
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
}

export default new MailingService();
