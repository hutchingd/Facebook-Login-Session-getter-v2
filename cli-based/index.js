const puppeteer = require('puppeteer-core');
const readline = require('readline');
const fs = require('fs');

function findChromium() {
    if (process.env.PUPPETEER_EXECUTABLE_PATH && fs.existsSync(process.env.PUPPETEER_EXECUTABLE_PATH)) {
        return process.env.PUPPETEER_EXECUTABLE_PATH;
    }
    const candidates = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/repl/tools/bin/chromium'];
    for (const c of candidates) if (fs.existsSync(c)) return c;
    return undefined;
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(res => rl.question(q, res));

async function initializeBrowser() {
    return puppeteer.launch({
        headless: true,
        executablePath: findChromium(),
        ignoreHTTPSErrors: true,
        args: ['--ignore-certificate-errors', '--disable-gpu', '--disable-software-rasterizer', '--disable-dev-shm-usage', '--no-sandbox', '--disable-setuid-sandbox', '--single-process', '--no-zygote']
    });
}

function extractResult(cookies) {
    const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');
    const jsonCookies = cookies.map(c => ({ domain: c.domain, expirationDate: c.expires, hostOnly: c.hostOnly, httpOnly: c.httpOnly, name: c.name, path: c.path, sameSite: c.sameSite, secure: c.secure, session: c.session, storeId: c.storeId, value: c.value }));
    const datrCookie = cookies.find(c => c.name === 'datr') || {};
    return { cookies: cookieString, jsonCookies, datr: datrCookie.value || null };
}

function isTwoFactor(url) { return /two_step_verification|checkpoint|approvals/i.test(url); }
function hasFullSession(cookies, url) { return cookies.some(c => c.name === 'c_user') && cookies.some(c => c.name === 'xs') && !isTwoFactor(url); }

async function main() {
    const email = await ask('Username/Email: ');
    const password = await ask('Password: ');

    const browser = await initializeBrowser();
    const page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    await page.goto('https://www.facebook.com/', { waitUntil: 'networkidle2' });
    await page.type('input[name="email"]', email);
    await page.type('input[name="pass"]', password);
    await page.focus('input[name="pass"]');
    await Promise.all([
        page.keyboard.press('Enter'),
        page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 }).catch(() => {})
    ]);
    await new Promise(r => setTimeout(r, 5000));

    let url = page.url();
    let cookies = await page.cookies();

    if (hasFullSession(cookies, url)) {
        const result = extractResult(cookies);
        fs.writeFileSync('cookies.json', JSON.stringify(result, null, 2));
        console.log('Saved to cookies.json');
        console.log(JSON.stringify(result, null, 2));
        await browser.close(); rl.close(); return;
    }

    if (isTwoFactor(url)) {
        const inputs = await page.$$('input');
        if (inputs.length) {
            const code = await ask('Enter authentication code: ');
            const input = await page.$('input');
            await input.type(code);
            await Promise.all([
                page.keyboard.press('Enter'),
                page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 }).catch(() => {})
            ]);
            await new Promise(r => setTimeout(r, 5000));
            url = page.url();
            cookies = await page.cookies();
            if (hasFullSession(cookies, url)) {
                const result = extractResult(cookies);
                fs.writeFileSync('cookies.json', JSON.stringify(result, null, 2));
                console.log('Saved to cookies.json');
                console.log(JSON.stringify(result, null, 2));
                await browser.close(); rl.close(); return;
            }
        } else {
            console.log('Waiting for approval. Please approve this login on your other device.');
            while (true) {
                await new Promise(r => setTimeout(r, 3000));
                try {
                    url = page.url();
                    cookies = await page.cookies();
                } catch (e) {
                    console.error('Session closed:', e.message);
                    break;
                }
                if (hasFullSession(cookies, url)) {
                    const result = extractResult(cookies);
                fs.writeFileSync('cookies.json', JSON.stringify(result, null, 2));
                console.log('Saved to cookies.json');
                console.log(JSON.stringify(result, null, 2));
                    await browser.close(); rl.close(); return;
                }
                if (!isTwoFactor(url)) break;
            }
        }
    }

    const loginFailed = await page.$('input[name="email"]');
    await browser.close();
    if (loginFailed) {
        console.error('Wrong username or password. Please try again.');
    } else {
        const result = extractResult(cookies);
        fs.writeFileSync('cookies.json', JSON.stringify(result, null, 2));
        console.log('Saved to cookies.json');
        console.log(JSON.stringify(result, null, 2));
    }
    rl.close();
}

main().catch(err => { console.error(err); rl.close(); process.exit(1); });
