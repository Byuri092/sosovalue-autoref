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

function getProxyAgent(proxyUrl) {
    const isSocks = proxyUrl.toLowerCase().startsWith('socks');
    if (isSocks) {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        return new SocksProxyAgent(proxyUrl);
    }
    return new HttpsProxyAgent(proxyUrl.startsWith('http') ? proxyUrl : `http://${proxyUrl}`);
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

function getRandomProxy() {
    if (!useProxy || proxyList.length === 0) return;
    
    const proxy = proxyList[Math.floor(Math.random() * proxyList.length)];
    try {
        axiosConfig.httpsAgent = getProxyAgent(proxy);
        console.log(chalk.yellow(`[*] Using proxy: ${proxy}`));
    } catch (error) {
        console.log(chalk.red(`[!] Error setting proxy: ${error.message}`));
    }
}

async function getDomains() {
    try {
        const key = String.fromCharCode(97 + Math.floor(Math.random() * 26)) + 
                   String.fromCharCode(97 + Math.floor(Math.random() * 26));
        
        console.log(chalk.cyan(`[*] Fetching domains with key: ${key}`));
        const response = await axios.get(`https://generator.email/search.php?key=${key}`, axiosConfig);
        if (response.data && Array.isArray(response.data)) {
            return response.data;
        }
        return [];
    } catch (error) {
        console.error(chalk.red(`[!] Error fetching domains: ${error.message}`));
        return [];
    }
}

function encodeBase64(str) {
    return Buffer.from(str).toString('base64');
}

function randomEmail(domain) {
    const firstName = faker.person.firstName();
    const lastName = faker.person.lastName();

    const cleanFirstName = firstName.replace(/[^a-zA-Z]/g, ''); 
    const cleanLastName = lastName.replace(/[^a-zA-Z]/g, '');   

    const randomNum = Math.floor(Math.random() * 900) + 100;
    const emailName = `${cleanFirstName.toLowerCase()}${cleanLastName.toLowerCase()}${randomNum}`;

    return {
        name: emailName,
        email: `${emailName}@${domain}`
    };
}

async function register(email, password) {
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

    try {
        const response = await axios.post('https://gw.sosovalue.com/usercenter/email/anno/sendRegisterVerifyCode/V2', data, axiosConfig);
        console.log(chalk.green(`[+] Registration successful for ${email}`));
        return response.data; 
    } catch (error) {
        console.log(chalk.red(`[!] Registration failed: ${error.message}`));
        throw error; 
    }
}

async function verifEmail(email, password, verifyCode, invitationCode) {
    console.log(chalk.cyan('[*] Verifying email...'));

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

    try {
        const response = await axios.post('https://gw.sosovalue.com/usercenter/user/anno/v3/register', data, axiosConfig);
        if(response.data.code === 0){
            console.log(chalk.green(`[+] Account created successfully with referral code: ${invitationCode}`));
            fs.appendFileSync('results.txt', `${email}|${password}|${invitationCode}\n`, 'utf8');
        }
        return response.data; 
    } catch (error) {
        console.log(chalk.red(`[!] Verification failed: ${error.message}`));
        throw error; 
    }
}

async function getOTP(email, domain) {
    for (let inboxNum = 1; inboxNum <= 9; inboxNum++) {
        console.log(chalk.cyan(`[*] Checking inbox ${inboxNum}...`));
        
        try {
            const response = await axios.get(`https://generator.email/inbox${inboxNum}/`, {
                ...axiosConfig,
                headers: {
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'accept-encoding': 'gzip, deflate, br, zstd',
                    'accept-language': 'en-US,en;q=0.9',
                    'cache-control': 'max-age=0',
                    'cookie': `_gid=GA1.2.2095327855.1735069411; __gads=ID=52c0ef95ece1dcd3:T=1723296851:RT=1735074556:S=ALNI_MY-N05jLZ5xHVJagROLPVaB7iMLRw; __gpi=UID=00000ebb7726ad8a:T=1723296851:RT=1735074556:S=ALNI_MZmpm9iDReVIrzNmydV67PPYNJhQw; __eoi=ID=50b40b8c429867d1:T=1723296851:RT=1735074556:S=AA-AfjYcohPcYMEyMXK2GgCw44zC; embx=%5B%${email}%40${domain}%22%2C%${email}%40${domain}%22%5D; _gat_gtag_UA_35796116_32=1; _ga=GA1.2.1660632963.1723296850; surl=${domain}/${email}; FCNEC=%5B%5B%22AKsRol-Lci8hCqIvO_xclbprHLQSsPjFOFt6Pu7w2kyTOo7Ahz83hFD5UlFG9kiq9pVZq23iGbdhLjdGucomp2CbWu2ZinNJRZYX3Xox3-XDAQ1imUiw8JveMOGFIHmDhh-EG1jHAFbEhKA-9N1aQd-DPg26Dn263A%3D%3D%22%5D%5D; _ga_1GPPTBHNKN=GS1.1.1735073618.15.1.1735074641.40.0.0`,
                    'priority': 'u=0, i',
                    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'same-origin',
                    'sec-fetch-user': '?1',
                    'upgrade-insecure-requests': '1',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
                }
            });

            const $ = cheerio.load(response.data);
            const containerElements = $('.e7m.container.to1').eq(2).html();
            const regex = /SoSoValue\s*-\s*(\d+)/;
            
            if (containerElements) {
                const match = containerElements.match(regex);
                if (match) {
                    const otp = match[1];
                    console.log(chalk.green(`[+] OTP found: ${otp}`));
                    return otp;
                }
            }

            console.log(chalk.yellow(`[!] No OTP found in inbox ${inboxNum}, waiting 3 seconds...`));
            await delay(3000);

        } catch (error) {
            console.log(chalk.red(`[!] Error checking inbox ${inboxNum}: ${error.message}`));
            await delay(3000);
        }
    }

    return false;
}

(async () => {
    console.clear();
    console.log(chalk.yellow('==============================================='));
    console.log(chalk.yellow('               SosoValue Autoref               '));
    console.log(chalk.yellow('                 By mamangzed                  '));
    console.log(chalk.yellow('             Revamped By IM-Hanzou             '));
    console.log(chalk.yellow('===============================================\n'));

    const proxyChoice = readlineSync.question(chalk.cyan('Use proxy? (y/n): ')).toLowerCase();
    useProxy = proxyChoice === 'y';

    if (useProxy) {
        if (!loadProxies()) {
            console.log(chalk.red('[!] Continuing without proxy...'));
            useProxy = false;
        }
    }

    const invite = readlineSync.question(chalk.cyan('Enter invitation code: '));
    const password = readlineSync.question(chalk.cyan('Enter password: '), { hideEchoBack: true }); 
    const accountCount = readlineSync.questionInt(chalk.cyan('Number of accounts to create: '));

    for (let i = 0; i < accountCount; i++) {
        console.log(chalk.magenta(`\n[Account ${i + 1}/${accountCount}]`));
        console.log(chalk.yellow('----------------------------------------'));

        if (useProxy) {
            getRandomProxy();
        }

        console.log(chalk.yellow('[*] Fetching new domains...'));
        const domains = await getDomains();
        if (domains.length === 0) {
            console.log(chalk.red('[!] No domains available, retrying...'));
            i--; 
            continue;
        }
        console.log(chalk.green(`[+] Found ${domains.length} domains\n`));

        const selectedDomain = domains[Math.floor(Math.random() * domains.length)];
        const randEmail = randomEmail(selectedDomain);

        try {
            await register(randEmail.email, password);

            let otp = false;
            let retryCount = 0;
            const maxRetries = 3;

            while (otp === false && retryCount < maxRetries) {
                otp = await getOTP(randEmail.name, selectedDomain);
                if (!otp) {
                    retryCount++;
                    console.log(chalk.yellow(`[!] Retry ${retryCount}/${maxRetries}`));
                }
            }

            if (!otp) {
                throw new Error('Failed to get OTP after maximum retries');
            }

            await verifEmail(randEmail.email, password, otp, invite);
            
            console.log(chalk.green(`[+] Account created successfully: ${randEmail.email}\n`));
        } catch (error) {
            console.log(chalk.red(`[!] Failed to create account: ${error.message}\n`));
            continue;
        }
    }

    console.log(chalk.green('\n[+] Registration process completed!'));
    console.log(chalk.cyan('[*] Check results.txt for account details'));
})();
