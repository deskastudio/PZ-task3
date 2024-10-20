import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

class FileEncryption {
    private algorithm: string;
    private ivLength: number;

    constructor(algorithm: string, ivLength: number) {
        this.algorithm = algorithm;
        this.ivLength = ivLength;
    }

    private async logMessage(message: string) {
        const logFilePath = path.join(__dirname, 'encryption_log.log');
        const timestamp = new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });
        const logEntry = `${timestamp} - ${message}\n`;
        await fs.appendFile(logFilePath, logEntry);
        console.log(message);  // Menampilkan pesan di console
    }

    private hashPassword(password: string): string {
        // Hashing password menggunakan SHA-256
        const hash = crypto.createHash('sha256').update(password).digest('hex');
        return hash;
    }

    async encryptFile(inputPath: string, password: string) {
        try {
            const hashedPassword = this.hashPassword(password); // Hashing password
            await this.logMessage(`Mulai mengenkripsi file ${inputPath} dengan password hash: ${hashedPassword}`);
            console.log(`Password hash yang digunakan untuk enkripsi: ${hashedPassword}`); // Menampilkan password hash di console
            const data = await fs.readFile(inputPath);
            const salt = crypto.randomBytes(16); // Membuat salt acak
            const key = crypto.scryptSync(password, salt, 32); // Membuat key dari password dan salt
            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipheriv(this.algorithm, key, iv);
            const encrypted = Buffer.concat([salt, iv, cipher.update(data), cipher.final()]); // Menyimpan salt, IV, dan data terenkripsi

            const encryptedFileName = `${path.basename(inputPath, path.extname(inputPath))}_encrypted${path.extname(inputPath)}`;
            await fs.writeFile(path.join(path.dirname(inputPath), encryptedFileName), encrypted);
            await this.logMessage(`Berhasil mengenkripsi file ${inputPath} menjadi ${encryptedFileName} dengan password hash: ${hashedPassword}`);
        } catch (error) {
            const errorMsg = `Error ketika mengenkripsi file: ${(error as Error).message}`;
            await this.logMessage(errorMsg);
            throw new Error(errorMsg);
        }
    }

    async decryptFile(inputPath: string, password: string) {
        try {
            await this.logMessage(`Mulai mendekripsi file ${inputPath} dengan password asli: ${password}`);
            console.log(`Password asli yang digunakan untuk dekripsi: ${password}`); // Menampilkan password asli di console
            const data = await fs.readFile(inputPath);
            const salt = data.slice(0, 16); // Mengambil salt dari data
            const iv = data.slice(16, 16 + this.ivLength); // Mengambil IV dari data
            const encryptedText = data.slice(16 + this.ivLength); // Memisahkan data terenkripsi
            const key = crypto.scryptSync(password, salt, 32);
            const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
            const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);

            const originalFileName = `${path.basename(inputPath, '_encrypted')}`;
            await fs.writeFile(path.join(path.dirname(inputPath), originalFileName), decrypted);
            await this.logMessage(`Berhasil mendekripsi file ${inputPath} menjadi ${originalFileName} dengan password asli: ${password}`);
        } catch (error) {
            const errorMsg = `Error ketika mendekripsi file: ${(error as Error).message}`;
            await this.logMessage(errorMsg);
            throw new Error(errorMsg);
        }
    }
}

const main = async () => {
    const [,, command, filePath, password] = process.argv;
    const fileEncryption = new FileEncryption('aes-256-cbc', 16);

    if (command === 'encrypt') {
        try {
            await fileEncryption.encryptFile(filePath, password);
            console.log(`File '${filePath}' berhasil dienkripsi.`);
        } catch (error) {
            console.error(`Error: ${(error as Error).message}`);
        }
    } else if (command === 'decrypt') {
        try {
            await fileEncryption.decryptFile(filePath, password);
            console.log(`File '${filePath}' berhasil didekripsi.`);
        } catch (error) {
            console.error(`Error: ${(error as Error).message}`);
        }
    } else {
        console.error('Perintah tidak dikenali. Gunakan "encrypt" atau "decrypt".');
    }
};

main().catch(err => console.error(err));
