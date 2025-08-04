import { createMessage, encrypt, readKey } from 'openpgp';

class EncryptionService {
    async encryptEmailContent(emailContent: string, armoredPublicKey: string): Promise<string> {
        try {
            const message = await createMessage({ text: emailContent });
            const encryptionKeys = await readKey({ armoredKey: armoredPublicKey });
            const encrypted = await encrypt({
                message,
                encryptionKeys,
            });

            return encrypted;
        } catch (error) {
            console.error('PGP encryption failed:', error);
            throw new Error(`PGP encryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    async isValidPublicKey(armoredPublicKey: string): Promise<boolean> {
        try {
            await readKey({ armoredKey: armoredPublicKey });
            return true;
        } catch {
            return false;
        }
    }
}

export default new EncryptionService();
