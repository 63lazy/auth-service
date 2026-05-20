const API_URL = 'http://localhost:3000/api';

let currentLoginMethod = 'password';
let currentUser = null;

function switchTab(tab) {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const tabs = document.querySelectorAll('.tab');

    if (tab === 'login') {
        loginForm.classList.add('active');
        registerForm.classList.remove('active');
        tabs[0].classList.add('active');
        tabs[1].classList.remove('active');
    } else {
        registerForm.classList.add('active');
        loginForm.classList.remove('active');
        tabs[0].classList.remove('active');
        tabs[1].classList.add('active');
    }

    clearMessages();
}

function selectLoginMethod(method) {
    currentLoginMethod = method;
    
    const options = document.querySelectorAll('.login-option');
    options.forEach(opt => opt.classList.remove('active'));
    
    const index = ['password', 'verification', 'signature'].indexOf(method);
    options[index].classList.add('active');

    const passwordGroup = document.getElementById('passwordLoginGroup');
    const verificationGroup = document.getElementById('verificationLoginGroup');
    const codeGroup = document.getElementById('verificationCodeGroup');

    if (method === 'password') {
        passwordGroup.classList.remove('hidden');
        verificationGroup.classList.add('hidden');
        codeGroup.classList.add('hidden');
    } else if (method === 'verification') {
        passwordGroup.classList.add('hidden');
        verificationGroup.classList.remove('hidden');
        codeGroup.classList.add('hidden');
    } else if (method === 'signature') {
        passwordGroup.classList.add('hidden');
        verificationGroup.classList.add('hidden');
        codeGroup.classList.add('hidden');
    }
}

function toggleCertGeneration() {
    const method = document.getElementById('regAuthMethod').value;
    const certGroup = document.getElementById('certGenerationGroup');
    
    if (method === 'signature' || method === 'all') {
        certGroup.classList.remove('hidden');
    } else {
        certGroup.classList.add('hidden');
    }
}

function showMessage(elementId, message, type) {
    const msgEl = document.getElementById(elementId);
    msgEl.textContent = message;
    msgEl.className = `message ${type}`;
    msgEl.style.display = 'block';
    
    setTimeout(() => {
        msgEl.style.display = 'none';
    }, 5000);
}

function clearMessages() {
    document.querySelectorAll('.message').forEach(msg => {
        msg.style.display = 'none';
    });
}

async function handleRegister() {
    const username = document.getElementById('regUsername').value.trim();
    const password = document.getElementById('regPassword').value;
    const email = document.getElementById('regEmail').value.trim();
    const phone = document.getElementById('regPhone').value.trim();
    const authMethod = document.getElementById('regAuthMethod').value;
    const generateCert = document.getElementById('generateCert').checked;

    if (!username || !password) {
        showMessage('registerMessage', '用户名和密码必填', 'error');
        return;
    }

    const registerBtn = document.getElementById('registerBtn');
    registerBtn.disabled = true;
    registerBtn.textContent = '注册中...';

    try {
        let certificate = null;

        if ((authMethod === 'signature' || authMethod === 'all') && generateCert) {
            showMessage('registerMessage', '正在生成密钥对和证书...', 'success');
            
            await cryptoModule.generateKeyPair();
            
            await cryptoModule.encryptPrivateKey(password);
            
            const cert = await cryptoModule.generateSelfSignedCertificate(username);
            certificate = JSON.stringify(cert);
            
            cryptoModule.saveToLocalStorage(username);
            
            showMessage('registerMessage', '密钥对和证书已生成并保存', 'success');
        }

        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                password,
                email,
                phone,
                certificate
            })
        });

        const result = await response.json();

        if (result.success) {
            showMessage('registerMessage', '注册成功！请登录', 'success');
            setTimeout(() => switchTab('login'), 1500);
        } else {
            showMessage('registerMessage', result.message, 'error');
        }
    } catch (error) {
        console.error('注册错误:', error);
        showMessage('registerMessage', '注册失败：' + error.message, 'error');
    } finally {
        registerBtn.disabled = false;
        registerBtn.textContent = '注册';
    }
}

async function handleLogin() {
    const username = document.getElementById('loginUsername').value.trim();

    if (!username) {
        showMessage('loginMessage', '请输入用户名', 'error');
        return;
    }

    const loginBtn = document.getElementById('loginBtn');
    loginBtn.disabled = true;
    loginBtn.textContent = '登录中...';

    try {
        if (currentLoginMethod === 'password') {
            await passwordLogin(username);
        } else if (currentLoginMethod === 'verification') {
            await verificationCodeLogin(username);
        } else if (currentLoginMethod === 'signature') {
            await signatureLogin(username);
        }
    } catch (error) {
        console.error('登录错误:', error);
        showMessage('loginMessage', '登录失败：' + error.message, 'error');
    } finally {
        loginBtn.disabled = false;
        loginBtn.textContent = '登录';
    }
}

async function passwordLogin(username) {
    const password = document.getElementById('loginPassword').value;

    if (!password) {
        showMessage('loginMessage', '请输入密码', 'error');
        return;
    }

    const response = await fetch(`${API_URL}/login/password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    const result = await response.json();

    if (result.success) {
        currentUser = result.user;
        showDashboard();
    } else {
        showMessage('loginMessage', result.message, 'error');
    }
}

async function requestVerificationCode() {
    const username = document.getElementById('loginUsername').value.trim();
    const contact = document.getElementById('verificationContact').value.trim();

    if (!username || !contact) {
        showMessage('loginMessage', '请输入用户名和联系方式', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/login/verification-code/request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, contact })
        });

        const result = await response.json();

        if (result.success) {
            showMessage('loginMessage', '验证码已发送，请检查', 'success');
            document.getElementById('verificationCodeGroup').classList.remove('hidden');
        } else {
            showMessage('loginMessage', result.message, 'error');
        }
    } catch (error) {
        console.error('请求验证码错误:', error);
        showMessage('loginMessage', '发送失败', 'error');
    }
}

async function verificationCodeLogin(username) {
    const code = document.getElementById('verificationCode').value.trim();

    if (!code) {
        showMessage('loginMessage', '请输入验证码', 'error');
        return;
    }

    const response = await fetch(`${API_URL}/login/verification-code/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, code })
    });

    const result = await response.json();

    if (result.success) {
        currentUser = result.user;
        showDashboard();
    } else {
        showMessage('loginMessage', result.message, 'error');
    }
}

async function signatureLogin(username) {
    try {
        const savedData = cryptoModule.loadFromLocalStorage(username);
        if (!savedData || !savedData.encryptedPrivateKey) {
            showMessage('loginMessage', '未找到本地密钥，请确认是否注册时生成了证书', 'error');
            return;
        }

        const password = await showPasswordDialog();
        if (!password) {
            showMessage('loginMessage', '需要密码解密私钥', 'error');
            return;
        }

        let privateKey;
        try {
            privateKey = await cryptoModule.decryptPrivateKey(savedData.encryptedPrivateKey, password);
        } catch (decryptError) {
            showMessage('loginMessage', '密码错误，无法解密私钥', 'error');
            return;
        }
        
        showMessage('loginMessage', '正在初始化签名认证...', 'success');

        const initResponse = await fetch(`${API_URL}/login/signature/init`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const initData = await initResponse.json();

        if (!initData.success) {
            showMessage('loginMessage', initData.message, 'error');
            return;
        }

        const { sessionId, randomR, timestamp } = initData;
        const messageToSign = randomR + timestamp.toString();
        
        const signature = await cryptoModule.signData(messageToSign);

        const verifyResponse = await fetch(`${API_URL}/login/signature/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sessionId,
                signature,
                timestamp
            })
        });

        const result = await verifyResponse.json();

        if (result.success) {
            currentUser = result.user;
            showDashboard();
        } else {
            showMessage('loginMessage', result.message, 'error');
        }
    } catch (error) {
        console.error('签名登录错误:', error);
        showMessage('loginMessage', '签名认证失败：' + error.message, 'error');
    }
}

function showDashboard() {
    document.getElementById('authForms').style.display = 'none';
    document.getElementById('userDashboard').style.display = 'block';

    document.getElementById('userId').textContent = currentUser.id;
    document.getElementById('displayUsername').textContent = currentUser.username;

    fetch(`${API_URL}/user/${currentUser.username}`)
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                document.getElementById('userEmail').textContent = data.user.email || '未设置';
                document.getElementById('userPhone').textContent = data.user.phone || '未设置';
                document.getElementById('certStatus').textContent = data.user.certificate ? '已认证' : '未认证';
            }
        })
        .catch(err => console.error('获取用户信息失败:', err));
}

function logout() {
    currentUser = null;
    document.getElementById('authForms').style.display = 'block';
    document.getElementById('userDashboard').style.display = 'none';
    
    document.getElementById('loginUsername').value = '';
    document.getElementById('loginPassword').value = '';
    document.getElementById('verificationContact').value = '';
    document.getElementById('verificationCode').value = '';
    
    clearMessages();
}

function showPasswordDialog() {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        `;

        const dialog = document.createElement('div');
        dialog.style.cssText = `
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 90%;
        `;

        const title = document.createElement('h3');
        title.textContent = '请输入密码';
        title.style.cssText = `
            margin-bottom: 20px;
            color: #333;
            text-align: center;
        `;

        const input = document.createElement('input');
        input.type = 'password';
        input.placeholder = '请输入密码以解密私钥';
        input.style.cssText = `
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 20px;
            box-sizing: border-box;
        `;

        const buttonGroup = document.createElement('div');
        buttonGroup.style.cssText = `
            display: flex;
            gap: 10px;
        `;

        const confirmBtn = document.createElement('button');
        confirmBtn.textContent = '确认';
        confirmBtn.style.cssText = `
            flex: 1;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
        `;

        const cancelBtn = document.createElement('button');
        cancelBtn.textContent = '取消';
        cancelBtn.style.cssText = `
            flex: 1;
            padding: 12px;
            background: #f0f0f0;
            color: #666;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
        `;

        buttonGroup.appendChild(cancelBtn);
        buttonGroup.appendChild(confirmBtn);
        dialog.appendChild(title);
        dialog.appendChild(input);
        dialog.appendChild(buttonGroup);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);

        input.focus();
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                confirmBtn.click();
            }
        });

        const closeDialog = () => {
            document.body.removeChild(overlay);
        };

        cancelBtn.addEventListener('click', () => {
            closeDialog();
            resolve(null);
        });

        confirmBtn.addEventListener('click', () => {
            const password = input.value;
            if (!password) {
                alert('请输入密码');
                return;
            }
            closeDialog();
            resolve(password);
        });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    switchTab('login');
    selectLoginMethod('password');
});
