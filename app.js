require('dotenv').config();
const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const cors = require('cors');
const cheerio = require('cheerio');

const app = express();
const port = process.env.PORT || 3000;


app.use(cors({
    origin: 'https://verdant-cucurucho-13134b.netlify.app',
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept', 'Cookie']
}));


app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 


app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`\n[${timestamp}] --- Incoming API Request ---`);
    console.log(`[${timestamp}] Method: ${req.method}, Path: ${req.originalUrl}`);
    console.log(`[${timestamp}] Request Body:`, req.body); 
    next();
});


function parseSetCookieHeaders(setCookieHeaders) {
    const cookies = {};
    let jsessionHcservicesValue = null;
    let hcservicesSessidValue = null;

    if (setCookieHeaders && Array.isArray(setCookieHeaders)) {
        setCookieHeaders.forEach(cookieString => {
            const parts = cookieString.split(';')[0].split('=');
            if (parts.length >= 2) {
                const name = parts[0].trim();
                const value = parts.slice(1).join('=').trim();

                const pathMatch = cookieString.match(/Path=([^;]+)/i);
                const cookiePath = pathMatch ? pathMatch[1].trim() : '/';

                if (name === 'JSESSIONID' || name === 'JSESSION') {
                    if (cookiePath === '/hcservices' || cookiePath === '/') {
                        jsessionHcservicesValue = value;
                    }
                    cookies[name] = value;
                } else if (name === 'HCSERVICES_SESSID') {
                    hcservicesSessidValue = value;
                    cookies[name] = value;
                } else {
                    cookies[name] = value;
                }
            }
        });
    }

    if (hcservicesSessidValue) {
        cookies['HCSERVICES_SESSID'] = hcservicesSessidValue;
    }
    if (jsessionHcservicesValue) {
        cookies['JSESSION'] = jsessionHcservicesValue;
        cookies['JSESSIONID'] = jsessionHcservicesValue; 
    }

    return cookies;
}

/**
 * Extracts a suitable session ID (either JSESSIONID, JSESSION, or HCSERVICES_SESSID) from parsed cookies.
 * @param {Object} cookies - The parsed cookies object.
 * @returns {string|null} The session ID string or null if not found.
 */
function getSessionIdFromCookies(cookies) {
    if (cookies && typeof cookies === 'object') {
        if (cookies['JSESSIONID']) {
            return cookies['JSESSIONID'];
        }
        if (cookies['JSESSION']) {
            return cookies['JSESSION'];
        }
        if (cookies['HCSERVICES_SESSID']) {
            return cookies['HCSERVICES_SESSID'];
        }
    }
    return null;
}

app.post('/api/benches/highcourt', async (req, res) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Handling High Court Benches request.`);

    const {
        state_code,
        appFlag = "web"
    } = req.body;

  
    if (!state_code) {
        return res.status(400).json({
            error: "Missing required parameters: state_code"
        });
    }

    const HCSERVICES_SESSID_HARDCODED = process.env.HCSERVICES_SESSID || "PUT_YOUR_FRESH_HCSERVICES_SESSID_HERE";
    const JSESSION_HARDCODED = process.env.JSESSION_BENCHES || "PUT_YOUR_FRESH_JSESSION_HERE";

    const targetUrl = `https://hcservices.ecourts.gov.in/hcservices/cases_qry/index_qry.php`;

    try {
        const payload = querystring.stringify({
            action_code: 'fillHCBench',
            state_code: state_code,
            appFlag: appFlag
        });

        const headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Cookie': `HCSERVICES_SESSID=${HCSERVICES_SESSID_HARDCODED}; JSESSION=${JSESSION_HARDCODED}`,
            'Origin': 'https://hcservices.ecourts.gov.in',
            'Priority': 'u=1, i',
            'Referer': 'https://hcservices.ecourts.gov.in/',
            'Sec-Ch-Ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Gpc': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest'
        };

        console.log(`[${timestamp}] Sending request to eCourts for benches with payload: ${payload}`);
        console.log(`[${timestamp}] Headers for benches request:`, headers);

        const response = await axios.post(targetUrl, payload, { headers: headers });

        console.log(`[${timestamp}] Received response from eCourts for benches. Status: ${response.status}`);
        let responseData = response.data;
        console.log(`[${timestamp}] Raw response data for benches:`, responseData);

        const benches = [];

     
        if (typeof responseData === 'string' && responseData.includes('~') && responseData.includes('#')) {
            const items = responseData.split('#');
            items.forEach(item => {
                const parts = item.split('~');
                if (parts.length === 2) {
                    const code = parts[0].trim();
                    const name = parts[1].trim();
                    if (code !== '' && name !== 'Select Bench') {
                        benches.push({ code: code, name: name });
                    }
                }
            });
        } else {
            console.warn(`[${timestamp}] WARN: Unexpected response format for benches. Expected delimited string.`);
        }

        console.log(`[${timestamp}] Parsed benches:`, benches);
        res.json({ benches: benches });

    } catch (error) {
        console.error(`[${timestamp}] ERROR in /api/benches/highcourt: ${error.message}`);
        if (error.response) {
            console.error(`[${timestamp}] Error Response Status: ${error.response.status}`);
            console.error(`[${timestamp}] Error Response Data Preview: ${String(error.response.data).substring(0, 500)}...`);
            console.error(`[${timestamp}] Error Response Headers:`, error.response.headers);
        } else if (error.request) {
            console.error(`[${timestamp}] No response received from target server.`);
        }
        res.status(500).json({ error: 'Failed to fetch benches', details: error.message });
    } finally {
        console.log(`[${timestamp}] --- /api/benches/highcourt request finished ---`);
    }
});



app.post('/api/captcha/highcourt', async (req, res) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Handling High Court Captcha request.`);

    const captchaUrl = 'https://hcservices.ecourts.gov.in/hcservices/securimage/securimage_show.php?135=null';

    try {
        const axiosConfig = {
            responseType: 'arraybuffer',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': 'https://hcservices.ecourts.gov.in/hcservices/',
                'Sec-Fetch-Dest': 'image',
                'Sec-Fetch-Mode': 'no-cors',
                'Sec-Fetch-Site': 'same-origin',
                'Priority': 'u=1, i',
            },
            timeout: 15000,
            validateStatus: function (status) {
                return status >= 200 && status < 300 || status === 302;
            }
        };

        let response = await axios.get(captchaUrl, axiosConfig);

        if (response.status === 302 && response.headers.location) {
            console.log(`[${timestamp}] Received 302 redirect for captcha. Following to: ${response.headers.location}`);
            const redirectUrl = response.headers.location;
            response = await axios.get(redirectUrl, axiosConfig);
        }

        const captchaImageBase64 = Buffer.from(response.data).toString('base64');
        const contentType = response.headers['content-type'] || 'image/png';

        const setCookieHeaders = response.headers['set-cookie'];
        const parsedCookies = parseSetCookieHeaders(setCookieHeaders);
        const sessionId = getSessionIdFromCookies(parsedCookies);

        console.log(`[${timestamp}] Captcha fetched. Image size: ${response.data.length} bytes.`);
        console.log(`[${timestamp}] Captcha response cookies (parsed):`, parsedCookies);
        console.log(`[${timestamp}] Captcha response session ID: ${sessionId}`);

        res.json({
            captchaImageBase64: `data:${contentType};base64,${captchaImageBase64}`,
            cookies: parsedCookies,
            sessionId: sessionId
        });
        console.log(`[${timestamp}] Captcha response sent to frontend.`);

    } catch (error) {
        console.error(`[${timestamp}] ERROR in /api/captcha/highcourt: ${error.message}`);
        if (error.response) {
            console.error(`[${timestamp}] Error Response Status: ${error.response.status}`);
            console.error(`[${timestamp}] Error Response Data Preview: ${String(error.response.data).substring(0, 500)}...`);
            console.error(`[${timestamp}] Error Response Headers:`, error.response.headers);
        } else if (error.request) {
            console.error(`[${timestamp}] No response received from target server during captcha fetch.`);
        }
        res.status(500).json({ error: 'Failed to fetch captcha', details: error.message });
        console.log(`[${timestamp}] Sent 500 Internal Server Error response for captcha.`);
    } finally {
        console.log(`[${timestamp}] --- /api/captcha/highcourt request finished ---`);
    }
});

app.post('/api/case/highcourt', async (req, res) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Handling High Court Case Verification request.`);

    const {
        captcha,
        petres_name,
        rgyear,
        caseStatusSearchType,
        f,
        court_code,
        state_code,
        court_complex_code,
        cookies: frontendCookiesObject,
        sessionId: frontendSessionId
    } = req.body;

    console.log(`[${timestamp}] Received parameters:`);
    console.log(`   - Captcha: ${captcha}`);
    console.log(`   - Pet/Res Name: ${petres_name}`);
    console.log(`   - Reg Year: ${rgyear}`);
    console.log(`   - Search Type: ${caseStatusSearchType}`);
    console.log(`   - F: ${f}`);
    console.log(`   - Court Code: ${court_code}`);
    console.log(`   - State Code: ${state_code}`);
    console.log(`   - Court Complex Code: ${court_complex_code}`);
    console.log(`   - Cookies Object from Frontend:`, frontendCookiesObject);
    console.log(`   - Session ID from Frontend (if provided): ${frontendSessionId}`);

    const cookieHeaderStringForExternalRequest = Object.entries(frontendCookiesObject || {})
        .map(([key, value]) => `${key}=${value}`)
        .join('; ');

    console.log(`[${timestamp}] Formatted Cookie header string for external request: "${cookieHeaderStringForExternalRequest}"`);

    if (!captcha || !petres_name || !rgyear || !caseStatusSearchType || !f ||
        !court_code || !state_code || !court_complex_code || !cookieHeaderStringForExternalRequest) {
        const missingFields = [];
        if (!captcha) missingFields.push('captcha');
        if (!petres_name) missingFields.push('petres_name');
        if (!rgyear) missingFields.push('rgyear');
        if (!caseStatusSearchType) missingFields.push('caseStatusSearchType');
        if (!f) missingFields.push('f');
        if (!court_code) missingFields.push('court_code');
        if (!state_code) missingFields.push('state_code');
        if (!court_complex_code) missingFields.push('court_complex_code');
        if (!cookieHeaderStringForExternalRequest) missingFields.push('cookiesString');

        console.error(`[${timestamp}] ERROR: Missing required fields: ${missingFields.join(', ')}`);
        return res.status(400).json({ error: `Missing required fields: ${missingFields.join(', ')}` });
    }
    console.log(`[${timestamp}] All required fields are present.`);

    const payload = querystring.stringify({
        action_code: 'showRecords',
        court_code,
        state_code,
        court_complex_code,
        captcha,
        petres_name,
        rgyear,
        caseStatusSearchType,
        f,
        appFlag: 'web'
    });
    console.log(`[${timestamp}] Constructed payload for eCourts: "${payload}"`);

    const caseVerificationUrl = 'https://hcservices.ecourts.gov.in/hcservices/cases_qry/index_qry.php';

    const headersToForward = {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'en-US,en;q=0.5',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': 'https://hcservices.ecourts.gov.in',
        'priority': 'u=1, i',
        'referer': 'https://hcservices.ecourts.gov.in/',
        'sec-ch-ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'sec-gpc': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
        'Cookie': cookieHeaderStringForExternalRequest,
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Content-Length': Buffer.byteLength(payload).toString()
    };
    console.log(`[${timestamp}] Headers for external request:`, headersToForward);

    try {
        const response = await axios.post(
            caseVerificationUrl,
            payload,
            { headers: headersToForward, timeout: 30000 }
        );

        console.log(`[${timestamp}] Received response from eCourts. Status: ${response.status}`);
        console.log(`[${timestamp}] Response Headers from eCourts:`, response.headers);

        let govData = response.data;
        console.log(`[${timestamp}] Raw response data from eCourts (first 500 chars): ${String(govData).substring(0, 500)}...`);

        if (typeof govData === 'string') {
            try {
                govData = JSON.parse(govData);
                console.log(`[${timestamp}] Successfully parsed main response data as JSON.`);
            } catch (jsonErr) {
                console.warn(`[${timestamp}] WARN: Main response data is a string but not valid JSON, leaving as string. Error: ${jsonErr.message}`);
                res.status(500).json({ error: 'Invalid JSON response from eCourts, possibly an error page.', details: jsonErr.message, rawResponse: govData.substring(0, 200) + "..." });
                console.log(`[${timestamp}] Sent 500 Internal Server Error for invalid JSON response.`);
                return;
            }
        }

        if (govData && typeof govData === 'object' && govData.con !== undefined) {
            let processedCon = govData.con;

            if (Array.isArray(processedCon) && processedCon.length === 1 && typeof processedCon[0] === 'string') {
                console.log(`[${timestamp}] Detected 'con' as single-element array containing a JSON string. Attempting to parse...`);
                try {
                    const tempParsed = JSON.parse(processedCon[0]);
                    if (Array.isArray(tempParsed)) {
                        processedCon = tempParsed;
                        console.log(`[${timestamp}] Successfully parsed string inside govData.con.`);
                    } else {
                        console.warn(`[${timestamp}] WARN: Parsed content of govData.con[0] is not an array after parsing. Keeping original.`);
                    }
                } catch (err) {
                    console.error(`[${timestamp}] ERROR: Failed to parse string inside govData.con: ${err.message}`);
                }
            } else if (typeof processedCon === 'string') {
                console.log(`[${timestamp}] Detected 'con' as a raw JSON string. Attempting to parse...`);
                try {
                    let tempParsed = JSON.parse(processedCon);
                    if (Array.isArray(tempParsed) && tempParsed.length > 0 && Array.isArray(tempParsed[0])) {
                        console.log(`[${timestamp}] Parsed 'con' string, and flattened nested array within it.`);
                        processedCon = tempParsed[0];
                    } else if (Array.isArray(tempParsed)) {
                        console.log(`[${timestamp}] Parsed 'con' string, no further flattening needed.`);
                        processedCon = tempParsed;
                    } else {
                        console.warn(`[${timestamp}] WARN: Parsed 'con' string is not an array. Keeping original.`);
                    }
                } catch (err) {
                    console.error(`[${timestamp}] ERROR: Failed to parse govData.con raw string: ${err.message}`);
                }
            } else if (Array.isArray(processedCon) && processedCon.length > 0 && Array.isArray(processedCon[0])) {
                console.log(`[${timestamp}] Detected 'con' as an array of arrays. Flattening.`);
                processedCon = processedCon[0];
            }
            govData.con = processedCon;
        }


        const newSetCookieHeaders = response.headers['set-cookie'];
        const updatedCookiesForFrontend = parseSetCookieHeaders(newSetCookieHeaders);
        const finalSessionId = getSessionIdFromCookies(updatedCookiesForFrontend) || frontendSessionId;

        console.log(`[${timestamp}] Final processed data to send to frontend:`, govData);
        console.log(`[${timestamp}] New/Updated cookies to send to frontend:`, updatedCookiesForFrontend);
        console.log(`[${timestamp}] Final Session ID for frontend:`, finalSessionId);

        res.json({
            sessionID: finalSessionId,
            data: {
                con: (govData.con && Array.isArray(govData.con)) ? govData.con : []
            },
            cookies: updatedCookiesForFrontend
        });
        console.log(`[${timestamp}] Case verification response sent successfully to frontend.`);

    } catch (error) {
        const errorTimestamp = new Date().toISOString();
        console.error(`[${errorTimestamp}] FATAL ERROR in /api/case/highcourt: ${error.message}`);
        if (error.code === 'ECONNRESET') {
            console.error(`[${errorTimestamp}] Connection reset by peer (socket hang up). This often indicates the target server closed the connection abruptly.`);
            console.error(`[${errorTimestamp}] Possible causes: IP blocking, rapid requests, session invalidation, or subtle header/payload issues.`);
        }
        if (error.response) {
            console.error(`[${errorTimestamp}] Error Response Status: ${error.response.status}`);
            console.error(`[${errorTimestamp}] Error Response Data Preview: ${String(error.response.data).substring(0, 500)}...`);
            console.error(`[${errorTimestamp}] Error Response Headers:`, error.response.headers);
        } else if (error.request) {
            console.error(`[${errorTimestamp}] No response received from target server (request sent but no reply).`);
        } else {
            console.error(`[${errorTimestamp}] Error setting up the request: ${error.message}`);
        }
        res.status(500).json({ error: 'Case verification failed', details: error.message, code: error.code });
        console.log(`[${errorTimestamp}] Sent 500 Internal Server Error response.`);
    } finally {
        console.log(`[${timestamp}] --- /api/case/highcourt request finished ---`);
    }
});


app.post('/api/case/details/highcourt', async (req, res) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Handling High Court Case Details request.`);

    const {
        hcservices_sessid,
        jsession_value,
        court_code,
        state_code,
        court_complex_code,
        case_no,
        cino,
        appFlag = ""
    } = req.body;

    console.log(`[${timestamp}] Received parameters for case details:`);
    console.log(`   - HCSERVICES_SESSID: ${hcservices_sessid}`);
    console.log(`   - JSESSION: ${jsession_value}`);
    console.log(`   - Court Code: ${court_code}`);
    console.log(`   - State Code: ${state_code}`);
    console.log(`   - Court Complex Code: ${court_complex_code}`);
    console.log(`   - Case No: ${case_no}`);
    console.log(`   - CINO: ${cino}`);
    console.log(`   - App Flag: ${appFlag}`);

    if (!hcservices_sessid || !jsession_value || !court_code || !state_code || !court_complex_code || !case_no || !cino) {
        const missingFields = [];
        if (!hcservices_sessid) missingFields.push('hcservices_sessid');
        if (!jsession_value) missingFields.push('jsession_value');
        if (!court_code) missingFields.push('court_code');
        if (!state_code) missingFields.push('state_code');
        if (!court_complex_code) missingFields.push('court_complex_code');
        if (!case_no) missingFields.push('case_no');
        if (!cino) missingFields.push('cino');
        console.error(`[${timestamp}] ERROR: Missing required parameters for case details: ${missingFields.join(', ')}`);
        return res.status(400).json({
            error: `Missing required parameters: ${missingFields.join(', ')}`
        });
    }

    const targetUrl = `https://hcservices.ecourts.gov.in/hcservices/cases_qry/o_civil_case_history.php`;

    try {
        const payload = querystring.stringify({
            court_code: court_code,
            state_code: state_code,
            court_complex_code: court_complex_code,
            case_no: case_no,
            cino: cino,
            appFlag: appFlag
        });

        const cookieHeaderString = `HCSERVICES_SESSID=${hcservices_sessid}; JSESSION=${jsession_value}`;

        const headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Cookie': cookieHeaderString,
            'Origin': 'https://hcservices.ecourts.gov.in',
            'Priority': 'u=1, i',
            'Referer': 'https://hcservices.ecourts.gov.in/',
            'Sec-Ch-Ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Gpc': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Length': Buffer.byteLength(payload).toString()
        };

        console.log(`[${timestamp}] Sending request to eCourts for case details with payload: ${payload}`);
        console.log(`[${timestamp}] Headers for case details request:`, headers);

        const response = await axios.post(targetUrl, payload, { headers: headers });

        console.log(`[${timestamp}] Received response from eCourts for case details. Status: ${response.status}`);
        console.log(`[${timestamp}] Response Headers from eCourts:`, response.headers);

        const html = response.data;
        console.log(`[${timestamp}] Raw HTML response from eCourts (first 500 chars): ${String(html).substring(0, 500)}...`);


        
        const $ = cheerio.load(html);

        const caseDetails = {};
        const $caseDetailsTable = $('.case_details_table');
        $caseDetailsTable.find('tr').each((i, row) => {
            const tds = $(row).find('td');
            if (tds.length >= 2) {
                const key = $(tds[0]).text().trim().replace(':', '');
                const value = $(tds[1]).text().trim();
                caseDetails[key] = value;
            }
        });

        const caseStatus = {};
        const $caseStatusTable = $('.table_r');
        $caseStatusTable.find('tr').each((i, row) => {
            const tds = $(row).find('td');
            if (tds.length >= 2) {
                const key = $(tds[0]).text().trim().replace(':', '');
                const value = $(tds[1]).text().trim();
                caseStatus[key] = value;
            }
        });

        const petitionerAdvocate = $('.Petitioner_Advocate_table').text().trim()
            .split('\n')
            .map(x => x.trim())
            .filter(Boolean);

        const respondentAdvocate = $('.Respondent_Advocate_table').text().trim()
            .split('\n')
            .map(x => x.trim())
            .filter(Boolean);

        const hearingHistory = [];
        const $hearingTable = $('.history_table');
        $hearingTable.find('tr').each((i, row) => {
            if (i === 0) return;
            const tds = $(row).find('td');
            if (tds.length >= 5) {
                hearingHistory.push({
                    causeListType: $(tds[0]).text().trim(),
                    judge: $(tds[1]).text().trim(),
                    businessOnDate: $(tds[2]).text().trim(),
                    hearingDate: $(tds[3]).text().trim(),
                    purpose: $(tds[4]).text().trim(),
                });
            }
        });

        const orders = [];
        const $orderTable = $('.order_table');
        $orderTable.find('tr').each((i, row) => {
            if (i === 0) return;
            const tds = $(row).find('td');
            if (tds.length >= 5) {
                orders.push({
                    orderNumber: $(tds[0]).text().trim(),
                    orderOn: $(tds[1]).text().trim(),
                    judge: $(tds[2]).text().trim(),
                    orderDate: $(tds[3]).text().trim(),
                    orderLink: $(tds[4]).find('a').attr('href') ?
                        'https://hcservices.ecourts.gov.in/hcservices/orders/' + $(tds[4]).find('a').attr('href') : null
                });
            }
        });

        const newSetCookieHeaders = response.headers['set-cookie'];
        const updatedCookiesForFrontend = parseSetCookieHeaders(newSetCookieHeaders);
        const finalSessionId = getSessionIdFromCookies(updatedCookiesForFrontend) || jsession_value || hcservices_sessid;

        console.log(`[${timestamp}] Parsed case details.`);
        console.log(`[${timestamp}] New/Updated cookies from details fetch:`, updatedCookiesForFrontend);
        console.log(`[${timestamp}] Final Session ID for frontend (from details):`, finalSessionId);

        const parsedData = {
            caseDetails,
            caseStatus,
            petitionerAdvocate,
            respondentAdvocate,
            hearingHistory,
            orders,
        };

        res.json({
            sessionID: finalSessionId,
            data: parsedData,
            cookies: updatedCookiesForFrontend
        });
        console.log(`[${timestamp}] Case details response sent successfully to frontend.`);

    } catch (error) {
        const errorTimestamp = new Date().toISOString();
        console.error(`[${errorTimestamp}] FATAL ERROR in /api/case/details/highcourt: ${error.message}`);
        if (error.code === 'ECONNRESET') {
            console.error(`[${errorTimestamp}] Connection reset by peer (socket hang up). This often indicates the target server closed the connection abruptly.`);
        }
        if (error.response) {
            console.error(`[${errorTimestamp}] Error Response Status: ${error.response.status}`);
            console.error(`[${errorTimestamp}] Error Response Data Preview: ${String(error.response.data).substring(0, 500)}...`);
            console.error(`[${errorTimestamp}] Error Response Headers:`, error.response.headers);
        } else if (error.request) {
            console.error(`[${errorTimestamp}] No response received from target server (request sent but no reply).`);
        } else {
            console.error(`[${errorTimestamp}] Error setting up the request: ${error.message}`);
        }
        res.status(500).json({ error: 'Failed to fetch case details', details: error.message, code: error.code });
        console.log(`[${errorTimestamp}] Sent 500 Internal Server Error response for case details.`);
    } finally {
        console.log(`[${timestamp}] --- /api/case/details/highcourt request finished ---`);
    }
});



app.post('/api/pdf/highcourt', async (req, res) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Handling High Court PDF Proxy request.`);

    console.log(`[${timestamp}] PDF Proxy: Received Request Body:`, req.body);

    const { pdfUrl, cookies: frontendCookiesObject } = req.body;

    if (!pdfUrl || !frontendCookiesObject) {
        console.error(`[${timestamp}] ERROR: Missing required parameters for PDF proxy: pdfUrl or cookies.`);
        return res.status(400).json({ error: 'Missing required parameters: pdfUrl and/or cookies' });
    }

    const cookieHeaderStringForExternalRequest = Object.entries(frontendCookiesObject)
        .map(([key, value]) => `${key}=${value}`)
        .join('; ');

    console.log(`[${timestamp}] PDF Proxy: Target URL: ${pdfUrl}`);
    console.log(`[${timestamp}] PDF Proxy: Using cookies: ${cookieHeaderStringForExternalRequest}`);

    try {
        const response = await axios.get(pdfUrl, {
            responseType: 'arraybuffer', 
            headers: {
                'Accept': 'application/pdf',
                'Accept-Language': 'en-US,en;q=0.5',
                'Cookie': cookieHeaderStringForExternalRequest,
                'Origin': 'https://hcservices.ecourts.gov.in',
                'Referer': 'https://hcservices.ecourts.gov.in/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Priority': 'u=1, i',
                'Connection': 'keep-alive',
                'Accept-Encoding': 'gzip, deflate, br',
            },
            timeout: 30000
        });

        // Set appropriate headers for the response back to the client
        res.setHeader('Content-Type', response.headers['content-type'] || 'application/pdf');
        res.setHeader('Content-Length', response.headers['content-length']);
        // Optional: If you want the browser to download it instead of opening in a new tab:
        res.setHeader('Content-Disposition', 'attachment; filename="order.pdf"');

        console.log(`[${timestamp}] PDF Proxy: Streaming PDF back to client. Content-Type: ${response.headers['content-type']}`);
        res.send(response.data); 

    } catch (error) {
        console.error(`[${timestamp}] ERROR in /api/pdf/highcourt: ${error.message}`);
        if (error.response) {
            console.error(`[${timestamp}] PDF Proxy Error Response Status: ${error.response.status}`);
            console.error(`[${timestamp}] PDF Proxy Error Response Headers:`, error.response.headers);
            console.error(`[${timestamp}] PDF Proxy Error Response Data Preview: ${Buffer.isBuffer(error.response.data) ? error.response.data.toString('utf8').substring(0, 500) : String(error.response.data).substring(0, 500)}...`);
            res.status(error.response.status).json({
                error: `Failed to fetch PDF from external service (Status: ${error.response.status})`,
                details: error.response.data.toString('utf8').substring(0, 500)
            });
        } else if (error.request) {
            console.error(`[${timestamp}] PDF Proxy: No response received from target PDF server.`);
            res.status(500).json({ error: 'No response from target PDF server.', details: error.message });
        } else {
            console.error(`[${timestamp}] PDF Proxy: Error setting up request:`, error.message);
            res.status(500).json({ error: 'Error setting up PDF fetch request.', details: error.message });
        }
    } finally {
        console.log(`[${timestamp}] --- /api/pdf/highcourt request finished ---`);
    }
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});