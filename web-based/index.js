const express = require('express');
const puppeteer = require('puppeteer-core');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

function findChromium() {
    if (process.env.PUPPETEER_EXECUTABLE_PATH && fs.existsSync(process.env.PUPPETEER_EXECUTABLE_PATH)) {
        return process.env.PUPPETEER_EXECUTABLE_PATH;
    }
    const candidates = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/repl/tools/bin/chromium'];
    for (const c of candidates) {
        if (fs.existsSync(c)) return c;
    }
    return undefined;
}

const app = express();
const sessions = new Map();

app.use(express.static(path.join(__dirname, 'public')));

async function initializeBrowser() {
    return puppeteer.launch({
        headless: true,
        executablePath: findChromium(),
        ignoreHTTPSErrors: true,
        args: [
            '--ignore-certificate-errors',
            '--disable-gpu',
            '--disable-software-rasterizer',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--single-process',
            '--no-zygote'
        ]
    });
}

function extractResult(cookies) {
    const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');
    const jsonCookies = cookies.map(c => ({
        domain: c.domain,
        expirationDate: c.expires,
        hostOnly: c.hostOnly,
        httpOnly: c.httpOnly,
        name: c.name,
        path: c.path,
        sameSite: c.sameSite,
        secure: c.secure,
        session: c.session,
        storeId: c.storeId,
        value: c.value
    }));
    const datrCookie = cookies.find(c => c.name === 'datr') || {};
    return { cookies: cookieString, jsonCookies, datr: datrCookie.value || null };
}

function isTwoFactor(url) {
    return /two_step_verification|checkpoint|approvals/i.test(url);
}

function hasFullSession(cookies, url) {
    return cookies.some(c => c.name === 'c_user') && cookies.some(c => c.name === 'xs') && !isTwoFactor(url);
}

async function doInitialLogin(email, password) {
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

    const url = page.url();
    const cookies = await page.cookies();

    if (hasFullSession(cookies, url)) {
        await browser.close();
        return { done: true, result: extractResult(cookies) };
    }

    if (isTwoFactor(url)) {
        try { await page.screenshot({ path: path.join(__dirname, 'public', '2fa.png'), fullPage: true }); } catch (e) {}
        const inputs = await page.$$('input');
        const sessionId = crypto.randomUUID();
        const session = { browser, page, email, password, status: inputs.length ? 'needsCode' : 'needsApproval', createdAt: Date.now() };
        sessions.set(sessionId, session);
        return { twoFactor: true, sessionId, needsCode: !!inputs.length };
    }

    const loginFailed = await page.$('input[name="email"]');
    await browser.close();
    if (loginFailed) {
        return { error: 'Wrong username or password. Please try again.' };
    }
    return { done: true, result: extractResult(cookies) };
}

async function pollSession(session, maxMs) {
    const start = Date.now();
    while (Date.now() - start < maxMs) {
        const url = session.page.url();
        const cookies = await session.page.cookies();
        if (hasFullSession(cookies, url)) {
            const result = extractResult(cookies);
            await session.browser.close();
            session.status = 'done';
            session.result = result;
            return result;
        }
        await new Promise(r => setTimeout(r, 2000));
    }
    return null;
}

app.get('/appstate', async (req, res) => {
    const { e: email, p: password } = req.query;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }
    try {
        const outcome = await doInitialLogin(email, password);
        if (outcome.error) return res.status(401).json({ error: outcome.error });
        if (outcome.done) return res.json(outcome.result);
        if (outcome.twoFactor) {
            const session = sessions.get(outcome.sessionId);
            if (outcome.needsCode) {
                return res.json({ needsCode: true, sessionId: outcome.sessionId, screenshotUrl: '/2fa.png' });
            }
            const result = await pollSession(session, 90000);
            if (result) return res.json(result);
            return res.json({ needsApproval: true, sessionId: outcome.sessionId, message: 'Waiting for approval. Please accept the login request on your other device.', screenshotUrl: '/2fa.png' });
        }
        return res.status(500).json({ error: 'Unknown login state.' });
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({ error: 'An error occurred during the login process.', details: String(error) });
    }
});

app.get('/status', async (req, res) => {
    const { session: sessionId } = req.query;
    const session = sessions.get(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found.' });
    if (session.status === 'done') return res.json(session.result);
    try {
        const url = session.page.url();
        const cookies = await session.page.cookies();
        if (hasFullSession(cookies, url)) {
            const result = extractResult(cookies);
            await session.browser.close();
            session.status = 'done';
            session.result = result;
            return res.json(result);
        }
        if (session.status === 'needsCode') {
            return res.json({ pending: true, needsCode: true, message: 'Enter the authentication code.' });
        }
        return res.json({ pending: true, needsApproval: true, message: 'Waiting for approval. Please accept the login request on your other device.' });
    } catch (error) {
        console.error('Status error:', error);
        return res.status(500).json({ error: String(error) });
    }
});

app.get('/submit-code', async (req, res) => {
    const { session: sessionId, code } = req.query;
    const session = sessions.get(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found.' });
    try {
        const input = await session.page.$('input');
        if (!input) return res.status(400).json({ error: 'No code input found.' });
        await input.type(code);
        await Promise.all([
            session.page.keyboard.press('Enter'),
            session.page.waitForNavigation({ waitUntil: 'networkidle2' }).catch(() => {})
        ]);
        const url = session.page.url();
        const cookies = await session.page.cookies();
        if (hasFullSession(cookies, url)) {
            const result = extractResult(cookies);
            await session.browser.close();
            session.status = 'done';
            session.result = result;
            return res.json(result);
        }
        return res.json({ pending: true, needsApproval: true, message: 'Waiting for approval. Please accept the login request on your other device.' });
    } catch (error) {
        console.error('Submit code error:', error);
        return res.status(500).json({ error: String(error) });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Express server is running on http://localhost:${PORT}`);
});
