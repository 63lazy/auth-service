class CryptoModule {
    constructor() {
        this.keyPair = null;
        this.encryptedPrivateKey = null;
        this.certificate = null;
        this.algorithm = 'RSA-OAEP';
    }

    async generateKeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'RSA-PSS',
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: 'SHA-256'
            },
            true,
            ['sign', 'verify']
        );

        const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        this.keyPair = {
            publicKey: this.arrayBufferToHex(publicKey),
            privateKey: this.arrayBufferToHex(privateKey),
            keyObject: keyPair
        };

        return this.keyPair;
    }

    arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    hexToArrayBuffer(hex) {
        const typedArray = new Uint8Array(hex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
        return typedArray.buffer;
    }

    deriveKeyBytes(password, salt = 'default_salt_for_key_derivation', iterations = 1000) {
        const derived = CryptoJS.PBKDF2(password, salt, {
            keySize: 256 / 32,
            iterations: iterations,
            hasher: CryptoJS.algo.SHA256
        });
        return derived;
    }

    async encryptPrivateKey(password) {
        if (!this.keyPair || !this.keyPair.keyObject) {
            throw new Error('密钥对未初始化，无法加密私钥');
        }
        
        const privateKeyToStore = {
            keyData: this.keyPair.privateKey,
            publicKey: this.keyPair.publicKey
        };
        const privateKeyJson = JSON.stringify(privateKeyToStore);
        
        // 使用密码字符串直接加密，CryptoJS 内部会自动处理 salt 和 key 派生
        const encrypted = CryptoJS.AES.encrypt(privateKeyJson, password);
        this.encryptedPrivateKey = encrypted.toString();
        
        return this.encryptedPrivateKey;
    }

    async decryptPrivateKey(encryptedData, password) {
        // 使用密码字符串直接解密，CryptoJS 内部会自动处理 salt 和 key 派生
        const decrypted = CryptoJS.AES.decrypt(encryptedData, password);
        const privateKeyJson = decrypted.toString(CryptoJS.enc.Utf8);
        
        if (!privateKeyJson) {
            console.error('解密失败：无法解密数据');
            throw new Error('解密失败，密码可能错误');
        }
        
        try {
            const privateKeyToStore = JSON.parse(privateKeyJson);
            const privateKeyHex = privateKeyToStore.keyData;
            const publicKeyData = privateKeyToStore.publicKey;
            
            console.log('解密成功，开始导入私钥...');
            
            const privateKeyBuffer = this.hexToArrayBuffer(privateKeyHex);
            const importedKey = await window.crypto.subtle.importKey(
                'pkcs8',
                privateKeyBuffer,
                {
                    name: 'RSA-PSS',
                    hash: 'SHA-256'
                },
                true,
                ['sign']
            );
            
            console.log('私钥导入成功');
            
            this.keyPair = {
                publicKey: publicKeyData,
                privateKey: privateKeyHex,
                keyObject: {
                    privateKey: importedKey
                }
            };
            
            return this.keyPair;
        } catch (error) {
            console.error('解密私钥失败:', error);
            throw new Error('解密失败：' + error.message);
        }
    }

    async generateSelfSignedCertificate(username, days = 365) {
        if (!this.keyPair) {
            throw new Error('请先生成密钥对');
        }

        const certData = {
            subject: `CN=${username},O=AuthSystem,C=CN`,
            issuer: `CN=AuthSystemCA,O=AuthSystem,C=CN`,
            serialNumber: this.generateSerialNumber(),
            validity: {
                notBefore: new Date().toISOString(),
                notAfter: new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()
            },
            publicKey: this.keyPair.publicKey,
            signature: null
        };

        const certContent = JSON.stringify({
            subject: certData.subject,
            issuer: certData.issuer,
            serialNumber: certData.serialNumber,
            validity: certData.validity,
            publicKey: certData.publicKey
        });

        const signature = await this.signData(certContent);
        certData.signature = signature;
        this.certificate = certData;

        return certData;
    }

    generateSerialNumber() {
        const array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async signData(data) {
        if (!this.keyPair || !this.keyPair.keyObject) {
            throw new Error('密钥对未初始化');
        }

        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        
        const signature = await window.crypto.subtle.sign(
            {
                name: 'RSA-PSS',
                saltLength: 32
            },
            this.keyPair.keyObject.privateKey,
            dataBuffer
        );

        return this.arrayBufferToHex(signature);
    }

    async verifySignature(data, signature, publicKey) {
        try {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            
            const signatureBuffer = this.hexToArrayBuffer(signature);
            
            const publicKeyObj = await window.crypto.subtle.importKey(
                'spki',
                this.hexToArrayBuffer(publicKey),
                {
                    name: 'RSA-PSS',
                    hash: 'SHA-256'
                },
                true,
                ['verify']
            );

            const isValid = await window.crypto.subtle.verify(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                publicKeyObj,
                signatureBuffer,
                dataBuffer
            );

            return isValid;
        } catch (error) {
            console.error('验证签名失败:', error);
            return false;
        }
    }

    saveToLocalStorage(username) {
        const data = {
            username: username,
            encryptedPrivateKey: this.encryptedPrivateKey,
            certificate: this.certificate,
            publicKey: this.keyPair ? this.keyPair.publicKey : null
        };
        
        localStorage.setItem('crypto_module_' + username, JSON.stringify(data));
    }

    loadFromLocalStorage(username) {
        const data = localStorage.getItem('crypto_module_' + username);
        if (data) {
            const parsed = JSON.parse(data);
            this.encryptedPrivateKey = parsed.encryptedPrivateKey;
            this.certificate = parsed.certificate;
            this.keyPair = {
                publicKey: parsed.publicKey
            };
            return parsed;
        }
        return null;
    }

    clearLocalStorage(username) {
        localStorage.removeItem('crypto_module_' + username);
    }

    getPublicKey() {
        return this.keyPair ? this.keyPair.publicKey : null;
    }

    getCertificate() {
        return this.certificate;
    }
}

const cryptoModule = new CryptoModule();
