import nodemailer from 'nodemailer';

import BaseService from './BaseService';

class MailingService extends BaseService {
    public domain: string;
    public selector: string;
    public privateKey: string;

    constructor() {
        super();
        this.checkEnvironment(['DKIM_PRIVATE_KEY', 'DKIM_DOMAIN', 'DKIM_SELECTOR']);

        this.domain = process.env.DKIM_DOMAIN || 'yourdomain.com';
        this.selector = process.env.DKIM_SELECTOR || 'default';
        this.privateKey = process.env.DKIM_PRIVATE_KEY || '';
    }

    async sendMail({ host, port, from, to, subject, text }: {
        host: string,
        port: number,
        from: string,
        to: string,
        subject: string,
        text: string,
    }) {
        const transporter = nodemailer.createTransport({
            host,
            port,
            secure: false,
            tls: { rejectUnauthorized: false },
            dkim: {
                domainName: this.domain,
                keySelector: this.selector,
                privateKey: this.privateKey
            }
        });

        await transporter.sendMail({
            from,
            to,
            subject,
            text,
        });
    }
}

export default new MailingService();
