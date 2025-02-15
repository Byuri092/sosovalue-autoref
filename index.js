const axios = require('axios');
const { default: chalk } = require('chalk');
const cheerio = require('cheerio');
const readlineSync = require('readline-sync');
const fs = require('fs');
const { faker } = require('@faker-js/faker');
const { HttpsProxyAgent } = require('https-proxy-agent');

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

let axiosConfig = {};
let proxyList = [];
let useProxy = false;
const maxRetries = 3;
let emailDomain = '';
let emailAddress = '';

// Função para obter o agente proxy
function getProxyAgent(proxyUrl) {
    try {
        const isSocks = proxyUrl.toLowerCase().startsWith('socks');
        if (isSocks) {
            const { SocksProxyAgent } = require('socks-proxy-agent');
            return new SocksProxyAgent(proxyUrl);
        }
        return new HttpsProxyAgent(proxyUrl.startsWith('http') ? proxyUrl : `http://${proxyUrl}`);
    } catch (error) {
        console.log(chalk.red(`[!] Error creating proxy agent: ${error.message}`));
        return null;
    }
}

// Carregar proxies
function loadProxies() {
    try {
        const proxyFile = fs.readFileSync('proxies.txt', 'utf8');
        proxyList = proxyFile.split('\n')
            .filter(line => line.trim())
            .map(proxy => {
                proxy = proxy.trim();
                if (!proxy.includes('://')) {
                    return `http://${proxy}`;
                }
                return proxy;
            });
            
        if (proxyList.length === 0) {
            throw new Error('No proxies found in proxies.txt');
        }
        console.log(chalk.green(`✓ Loaded ${proxyList.length} proxies from proxies.txt`));
        return true;
    } catch (error) {
        console.error(chalk.red(`[!] Error loading proxies: ${error.message}`));
        return false;
    }
}

// Carregar códigos de referência
async function loadRefCodes() {
    try {
        if (!fs.existsSync('refcode.txt')) {
            console.log(chalk.red('[!] refcode.txt not found'));
            return [];
        }
        const codes = fs.readFileSync('refcode.txt', 'utf8')
            .split('\n')
            .map(code => code.trim())
            .filter(code => code.length > 0);
        
        if (codes.length === 0) {
            console.log(chalk.red('[!] No referral codes found in refcode.txt'));
            return [];
        }
        
        console.log(chalk.green(`[+] Loaded ${codes.length} referral codes from refcode.txt`));
        return codes;
    } catch (error) {
        console.log(chalk.red(`[!] Error loading referral codes: ${error.message}`));
        return [];
    }
}

// Função para verificar o IP
async function checkIP() {
    try {
        const response = await axios.get('https://api.ipify.org?format=json', axiosConfig);
        const ip = response.data.ip;
        console.log(chalk.green(`[+] Current IP: ${ip}`));
        return true;
    } catch (error) {
        console.log(chalk.red(`[!] Failed to get IP: ${error.message}`));
        return false;
    }
}

// Função para obter um proxy aleatório
async function getRandomProxy() {
    if (!useProxy || proxyList.length === 0) {
        axiosConfig = {};
        await checkIP();
        return true;
    }
    
    let proxyAttempt = 0;
    while (proxyAttempt < proxyList.length) {
        const proxy = proxyList[Math.floor(Math.random() * proxyList.length)];
        try {
            const agent = getProxyAgent(proxy);
            if (!agent) continue;
            
            axiosConfig.httpsAgent = agent;
            await checkIP();
            return true;
        } catch (error) {
            proxyAttempt++;
        }
    }
    
    console.log(chalk.red('[!] Using default IP'));
    axiosConfig = {};
    await checkIP();
    return false;
}

// Função para gerar e-mails aleatórios com a nova API
async function generateRandomEmail() {
    try {
        const response = await axios.get('https://www.1secmail.com/api/v1/?action=genRandomMailbox');
        if (response.data && response.data[0]) {
            emailDomain = response.data[0].split('@')[1]; // Pegando o domínio do e-mail gerado
            emailAddress = response.data[0]; // E-mail completo
            console.log(chalk.green(`[+] Random email generated: ${emailAddress}`));
            return response.data[0];
        } else {
            throw new Error('Failed to generate random email');
        }
    } catch (error) {
        console.error(chalk.red(`[!] Error generating random email: ${error.message}`));
        throw error;
    }
}

// Função para obter o OTP de login
async function getOTPLogin(email) {
    if (!email || typeof email !== 'string') {
        throw new Error('Email must be a string');
    }

    const data = { email: email };

    try {
        const response = await axios.post('https://gw.sosovalue.com/usercenter/email/anno/sendNewDeviceVerifyCode', data, axiosConfig);
        if(response.data.code === 0){
            console.log(chalk.cyan(`[*] OTP code sent successfully`)); 
        }
        return response.data; 
    } catch (error) {
        console.error(chalk.red(`[!] Error: ${error.response ? error.response.data : error.message}`));
        throw error;
    }
}

// Função para capturar o OTP de um email
async function getOTP() {
    try {
        // Gerar um e-mail aleatório
        const randomEmail = await generateRandomEmail();

        // Aguardar 3 segundos para verificar a caixa de entrada
        await delay(3000);

        console.log(chalk.cyan(`[*] Checking inbox for OTP...`));
        
        // Aqui você pode adicionar a lógica para verificar a caixa de entrada
        // Usando a nova API ou qualquer outra lógica necessária para pegar o OTP
    } catch (error) {
        console.log(chalk.red(`[!] Error while getting OTP: ${error.message}`));
    }
}

async function verifLogin(email, password, verifyCode) {
    if (!email || typeof email !== 'string') {
        throw new Error('Email must be a string');
    }
    if (!password || typeof password !== 'string') {
        throw new Error('Password must be a string');
    }
    if (!verifyCode || typeof verifyCode !== 'string') {
        throw new Error('VerifyCode must be a string');
    }

    const encodedPassword = encodeBase64(password);

    const data = {
        isDifferent: true,
        password: encodedPassword,
        loginName: email,
        type: 'portal',
        verifyCode: verifyCode,
    };

    try {
        const response = await axios.post('https://gw.sosovalue.com/authentication/auth/v2/emailPasswordLogin', data, axiosConfig);
        if(response.data.code === 0){
            console.log(chalk.green(`[+] Login successful, wallet address: ${response.data.data.walletAddress}`)); 
        }
        return response.data; 
    } catch (error) {
        console.error(chalk.red(`[!] Error: ${error.response ? error.response.data : error.message}`));
        throw error;
    }
}

async function loginToken(token, email, password) {
    try {
        const response = await axios.get('https://gw.sosovalue.com/authentication/user/getUserInfo', {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
            ...axiosConfig
        });
        fs.appendFileSync('results.txt', `${email}|${password}|${response.data.data.invitationCode}|isRobot: ${response.data.data.isRobot}|isSuspicious: ${response.data.data.isSuspicious}\n`, 'utf8');
        fs.appendFileSync('refcodeonly.txt', `${response.data.data.invitationCode}\n`, 'utf8');
        return response;
    } catch (error) {
        console.error(chalk.red('[!] Error:', error.message));
        return false;
    }
}

async function processRegistration(accountIndex, totalAccounts, invite, password) {
    let success = false;
    let attempt = 0;

    while (!success && attempt < maxRetries) {
        attempt++;
        console.log(chalk.magenta(`\n[Account ${accountIndex + 1}/${totalAccounts}]`));
        console.log(chalk.yellow('----------------------------------------'));

        try {
            if (useProxy) {
                await getRandomProxy();
            }

            const domains = await getDomains();
            if (domains.length === 0) {
                throw new Error('Failed to fetch domains');
            }

            console.log(chalk.green(`[+] Found ${domains.length} domains\n`));
            const selectedDomain = domains[Math.floor(Math.random() * domains.length)];
            const randEmail = randomEmail(selectedDomain);

            const regis = await register(randEmail.email, password);
            if (regis.code !== 0) {
                console.log(chalk.red(`[!] Email ${randEmail.email} is already in use`));
                continue;
            }

            const otp = await getOTP(randEmail.name, selectedDomain);
            if (!otp) {
                throw new Error('Failed to get registration OTP');
            }

            await verifEmail(randEmail.email, password, otp, invite);
            
            console.log(chalk.green(`[+] Account created successfully: ${randEmail.email}`));
            
            console.log(chalk.cyan(`[*] Attempting login for account: ${randEmail.email}`));
            const regLogin = await getOTPLogin(randEmail.email);
            if (regLogin.code !== 0) {
                console.log(chalk.red(`[!] Login request failed for ${randEmail.email}`));
                continue;
            }

            await delay(5000);
            const loginOtp = await getOTP(randEmail.name, selectedDomain, 1);
            if (!loginOtp) {
                throw new Error('Failed to get login OTP');
            }

            const verifLogins = await verifLogin(randEmail.email, password, loginOtp);
            if (verifLogins.code !== 0) {
                console.log(chalk.red(`[!] Login verification failed for ${randEmail.email}`));
                continue;
            }

            const login = await loginToken(verifLogins.data.token, randEmail.email, password);
            if (!login || (login.data && login.data.code !== 0)) {
                console.log(chalk.red(`[!] Failed to get user info for ${randEmail.email}`));
                continue;
            }

            console.log(chalk.cyan('\n[+] Login successful with data:'));
            console.log(chalk.cyan(`    → Username: ${login.data.data.username}`));
            console.log(chalk.cyan(`    → Invitation Code: ${login.data.data.invitationCode}`));
            console.log(chalk.cyan(`    → Is Robot: ${login.data.data.isRobot}`));
            console.log(chalk.cyan(`    → Is Suspicious: ${login.data.data.isSuspicious}`));
            console.log(chalk.cyan(`    → Wallet Address: ${verifLogins.data.walletAddress}\n`));
            
            success = true;

        } catch (error) {
            if (attempt === maxRetries) {
                console.log(chalk.red(`[!] Failed to complete account creation after ${maxRetries} attempts: ${error.message}\n`));
                return false;
            }
            console.log(chalk.yellow(`[!] Process failed, starting attempt ${attempt + 1}...\n`));
            await delay(3000);
        }
    }
    return success;
}

async function processSingleMode(invite, password, accountCount) {
    let successfulAccounts = 0;
    let failedAccounts = 0;

    for (let i = 0; i < accountCount; i++) {
        const success = await processRegistration(i, accountCount, invite, password);
        if (success) {
            successfulAccounts++;
        } else {
            failedAccounts++;
        }
    }

    return { successfulAccounts, failedAccounts };
}

async function processMultiMode(refCodes, password, accountsPerCode) {
    let totalSuccessful = 0;
    let totalFailed = 0;
    
    for (let i = 0; i < refCodes.length; i++) {
        const invite = refCodes[i];
        console.log(chalk.yellow(`\n===============================================`));
        console.log(chalk.yellow(`Processing Referral Code ${i + 1}/${refCodes.length}: ${invite}`));
        console.log(chalk.yellow(`===============================================\n`));

        let successfulAccounts = 0;
        let failedAccounts = 0;

        for (let j = 0; j < accountsPerCode; j++) {
            const success = await processRegistration(j, accountsPerCode, invite, password);
            if (success) {
                successfulAccounts++;
                totalSuccessful++;
            } else {
                failedAccounts++;
                totalFailed++;
            }
        }

        console.log(chalk.cyan(`\n[*] Results for code ${invite}:`));
        console.log(chalk.green(`[+] Successfully created: ${successfulAccounts} accounts`));
        console.log(chalk.red(`[+] Failed to create: ${failedAccounts} accounts`));
    }

    return { totalSuccessful, totalFailed };
}

(async () => {
    console.clear();
    console.log(chalk.yellow('==============================================='));
    console.log(chalk.yellow('               SosoValue Autoref               '));
    console.log(chalk.yellow('                 By mamangzed                  '));
    console.log(chalk.yellow('             Revamped By IM-Hanzou            '));
    console.log(chalk.yellow('===============================================\n'));

    const ipChoice = readlineSync.question(chalk.cyan('Using Proxy? (y/n): ')).toLowerCase();
    useProxy = ipChoice === 'y';

    if (useProxy) {
        loadProxies();
    }

    const mode = readlineSync.question(chalk.cyan('Choose mode (1: Single Code, 2: Multiple Codes from refcode.txt): '));
    const password = readlineSync.question(chalk.cyan('Enter password for accounts: '), { hideEchoBack: true });

    let results;

    if (mode === '1') {
        const invite = readlineSync.question(chalk.cyan('Enter invitation code: '));
        const accountCount = readlineSync.questionInt(chalk.cyan('Number of accounts to create: '));
        results = await processSingleMode(invite, password, accountCount);
    } else if (mode === '2') {
        const refCodes = await loadRefCodes();
        if (refCodes.length === 0) {
            console.log(chalk.red('[!] Cannot proceed without referral codes'));
            return;
        }
        const accountsPerCode = readlineSync.questionInt(chalk.cyan('Number of accounts to create per referral code: '));
        results = await processMultiMode(refCodes, password, accountsPerCode);
    } else {
        console.log(chalk.red('[!] Invalid mode selected'));
        return;
    }

    console.log(chalk.green('\n==============================================='));
    console.log(chalk.green(`[+] Registration process completed!`));
    console.log(chalk.cyan(`[*] Successfully created: ${results.totalSuccessful || results.successfulAccounts} accounts`));
    console.log(chalk.red(`[*] Failed to create: ${results.totalFailed || results.failedAccounts} accounts`));
    console.log(chalk.cyan('[*] Check results.txt for account details'));
    console.log(chalk.green('===============================================\n'));
})();
