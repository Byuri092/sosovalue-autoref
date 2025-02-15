const axios = require('axios');
const { default: chalk } = require('chalk');
const readlineSync = require('readline-sync');
const fs = require('fs');
const { faker } = require('@faker-js/faker');
const { HttpsProxyAgent } = require('https-proxy-agent');

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

let axiosConfig = {};
let proxyList = [];
let useProxy = false;
const maxRetries = 3;

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

async function getTempMailEmail() {
    try {
        const response = await axios.get('https://api.tempmail.lol/generate');
        if (response.data && response.data.address) {
            return response.data;
        }
        throw new Error('Failed to generate email');
    } catch (error) {
        console.error(chalk.red(`[!] Error generating email: ${error.message}`));
        throw error;
    }
}

async function checkEmailAvailability(email) {
    try {
        const response = await axios.post('https://gw.sosovalue.com/usercenter/email/anno/checkEmail', { email }, axiosConfig);
        return response.data.code === 0; // Retorna true se o e-mail estiver disponível
    } catch (error) {
        console.error(chalk.red(`[!] Error checking email availability: ${error.message}`));
        return false;
    }
}

async function getTempMailOTP(email) {
    try {
        const response = await axios.get(`https://api.tempmail.lol/activity/${email}`);
        if (response.data && response.data.length > 0) {
            const latestEmail = response.data[0];
            const otpMatch = latestEmail.body.match(/SoSoValue\s*-\s*(\d+)/);
            if (otpMatch) {
                return otpMatch[1];
            }
        }
        throw new Error('No OTP found');
    } catch (error) {
        console.error(chalk.red(`[!] Error fetching OTP: ${error.message}`));
        throw error;
    }
}

function encodeBase64(str) {
    return Buffer.from(str).toString('base64');
}

async function register(email, password) {
    let attempt = 0;
    while (attempt < maxRetries) {
        try {
            console.log(chalk.cyan(`[*] Processing registration for ${email}...`));
            
            if (!email || typeof email !== 'string') {
                throw new Error('Email must be a string');
            }

            if (!password || typeof password !== 'string') {
                throw new Error('Password must be a string');
            }

            const encodedPassword = encodeBase64(password);
            
            const data = {
                password: encodedPassword, 
                rePassword: encodedPassword, 
                username: "NEW_USER_NAME_02", 
                email: email 
            };

            const response = await axios.post('https://gw.sosovalue.com/usercenter/email/anno/sendRegisterVerifyCode/V2', data, axiosConfig);
            console.log(chalk.green(`[+] Registration successful for ${email}`));
            return response.data;
        } catch (error) {
            console.log(chalk.red(`[!] Registration failed: ${error.message}`));
            if (error.message.includes('ECONNREFUSED') || error.message.includes('ETIMEDOUT')) {
                await getRandomProxy();
            }
            attempt++;
            if (attempt < maxRetries) {
                await delay(2000);
            } else {
                throw error;
            }
        }
    }
}

async function verifEmail(email, password, verifyCode, invitationCode) {
    let attempt = 0;
    while (attempt < maxRetries) {
        try {
            console.log(chalk.cyan(`[*] Verifying email...`));

            const encodedPassword = encodeBase64(password);
            const data = {
                password: encodedPassword,
                rePassword: encodedPassword, 
                username: "NEW_USER_NAME_02", 
                email: email,
                verifyCode: verifyCode,
                invitationCode: invitationCode,
                invitationFrom: null
            };

            const response = await axios.post('https://gw.sosovalue.com/usercenter/user/anno/v3/register', data, axiosConfig);
            if(response.data.code === 0){
                console.log(chalk.green(`[+] Account created successfully with referral code: ${invitationCode}`));
                return response.data;
            }
            throw new Error(`Invalid response code: ${response.data.code}`);
        } catch (error) {
            console.log(chalk.red(`[!] Verification failed: ${error.message}`));
            if (error.message.includes('ECONNREFUSED') || error.message.includes('ETIMEDOUT')) {
                await getRandomProxy();
            }
            attempt++;
            if (attempt < maxRetries) {
                await delay(2000);
            } else {
                throw error;
            }
        }
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

            let emailAvailable = false;
            let emailData;

            // Tenta gerar um e-mail disponível
            while (!emailAvailable) {
                emailData = await getTempMailEmail();
                const email = emailData.address;

                console.log(chalk.cyan(`[*] Checking if email ${email} is available...`));
                emailAvailable = await checkEmailAvailability(email);

                if (!emailAvailable) {
                    console.log(chalk.yellow(`[!] Email ${email} is already in use, generating a new one...`));
                    await delay(2000); // Aguarda 2 segundos antes de tentar novamente
                }
            }

            const email = emailData.address;
            console.log(chalk.green(`[+] Email ${email} is available`));

            const regis = await register(email, password);
            if (regis.code !== 0) {
                console.log(chalk.red(`[!] Registration failed for ${email}`));
                continue;
            }

            await delay(10000); // Aguarda o e-mail de OTP chegar
            const otp = await getTempMailOTP(email);
            if (!otp) {
                throw new Error('Failed to get registration OTP');
            }

            await verifEmail(email, password, otp, invite);
            console.log(chalk.green(`[+] Account created successfully: ${email}`));

            console.log(chalk.cyan(`[*] Attempting login for account: ${email}`));
            const regLogin = await getOTPLogin(email);
            if (regLogin.code !== 0) {
                console.log(chalk.red(`[!] Login request failed for ${email}`));
                continue;
            }

            await delay(5000);
            const loginOtp = await getTempMailOTP(email);
            if (!loginOtp) {
                throw new Error('Failed to get login OTP');
            }

            const verifLogins = await verifLogin(email, password, loginOtp);
            if (verifLogins.code !== 0) {
                console.log(chalk.red(`[!] Login verification failed for ${email}`));
                continue;
            }

            const login = await loginToken(verifLogins.data.token, email, password);
            if (!login || (login.data && login.data.code !== 0)) {
                console.log(chalk.red(`[!] Failed to get user info for ${email}`));
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

    const ipChoice = readlineSync.question(chalk.cyan('Using Proxy? (y/n): '), {
        limit: ['y', 'n'],
        limitMessage: chalk.red('[!] Invalid choice. Please enter "y" or "n".')
    });
    useProxy = ipChoice === 'y';

    if (useProxy) {
        loadProxies();
    }

    const mode = readlineSync.question(chalk.cyan('Choose mode (1: Single Code, 2: Multiple Codes from refcode.txt): '), {
        limit: ['1', '2'],
        limitMessage: chalk.red('[!] Invalid mode selected. Please choose 1 or 2.')
    });
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
    }

    console.log(chalk.green('\n==============================================='));
    console.log(chalk.green(`[+] Registration process completed!`));
    console.log(chalk.cyan(`[*] Successfully created: ${results.totalSuccessful || results.successfulAccounts} accounts`));
    console.log(chalk.red(`[*] Failed to create: ${results.totalFailed || results.failedAccounts} accounts`));
    console.log(chalk.cyan('[*] Check results.txt for account details'));
    console.log(chalk.green('===============================================\n'));
})();
