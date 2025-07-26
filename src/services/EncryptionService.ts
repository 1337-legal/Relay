import { createMessage, encrypt, readKey } from 'openpgp';

class EncryptionService {
    static async encryptEmailContent(emailContent: string, armoredPublicKey: string): Promise<string> {
        const message = await createMessage({ text: emailContent });
        const encryptionKeys = await readKey({ armoredKey: armoredPublicKey });
        const encrypted = await encrypt({
            message,
            encryptionKeys,
        });

        return encrypted;
    }
}

export default EncryptionService;
