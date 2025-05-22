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

    if (setCookieHeaders && Array.isArray(setCookieHeaders)) {
        setCookieHeaders.forEach(cookieString => {
            const parts = cookieString.split(';')[0].split('=');
            if (parts.length >= 2) {
                const name = parts[0].trim();
                const value = parts.slice(1).join('=').trim();
                const pathMatch = cookieString.match(/Path=([^;]+)/i);
                const cookiePath = pathMatch ? pathMatch[1].trim() : '/';

                if (name === 'JSESSIONID' || name === 'JSESSION') {
                    if (cookiePath === '/hcservices') {
                        jsessionHcservicesValue = value;
                    }
                    cookies[name] = value;
                } else {
                    cookies[name] = value;
                }
            }
        });
    }

    if (jsessionHcservicesValue) {
        cookies['JSESSIONID'] = jsessionHcservicesValue;
        cookies['JSESSION'] = jsessionHcservicesValue;
    }

    return cookies;
}

function getSessionIdFromCookies(cookies) {
    if (cookies && typeof cookies === 'object') {
        if (cookies['JSESSIONID']) {
            return cookies['JSESSIONID'];
        }
        if (cookies['HCSERVICES_SESSID']) {
            return cookies['HCSERVICES_SESSID'];
        }
    }
    return null;
}

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
    console.log(`  - Captcha: ${captcha}`);
    console.log(`  - Cookies Object from Frontend:`, frontendCookiesObject);
    console.log(`  - Session ID from Frontend (if provided): ${frontendSessionId}`);

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
                res.status(500).json({ error: 'Invalid JSON response from eCourts', details: jsonErr.message });
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
            }
            else if (typeof processedCon === 'string') {
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
            }
            else if (Array.isArray(processedCon) && processedCon.length > 0 && Array.isArray(processedCon[0])) {
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

// NEW ROUTE: For fetching full case details
app.post('/api/case/details/highcourt', async (req, res) => {
    // Extracting all parameters as per the new curl request
    const {
        hcservices_sessid, // From the HCSERVICES_SESSID cookie
        jsession_value,    // From the JSESSION cookie
        court_code,
        state_code,
        court_complex_code,
        case_no,           // This is now the full case number like 201300062112021
        cino,
        appFlag = ""       // Default to empty string if not provided, as in curl
    } = req.body;

    // Validate essential parameters for the new endpoint
    if (!hcservices_sessid || !jsession_value || !court_code || !state_code || !court_complex_code || !case_no || !cino) {
        return res.status(400).json({
            error: "Missing required parameters: hcservices_sessid, jsession_value, court_code, state_code, court_complex_code, case_no, cino"
        });
    }

    const targetUrl = `https://hcservices.ecourts.gov.in/hcservices/cases_qry/o_civil_case_history.php`;

    try {
        const response = await axios.post(targetUrl, querystring.stringify({
            court_code: court_code,
            state_code: state_code,
            court_complex_code: court_complex_code,
            case_no: case_no,
            cino: cino,
            appFlag: appFlag
        }), {
            headers: {
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Cookie': `HCSERVICES_SESSID=${hcservices_sessid}; JSESSION=${jsession_value}`,
                'Origin': 'https://hcservices.ecourts.gov.in',
                'Priority': 'u=1, i',
                'Referer': 'https://hcservices.ecourts.gov.in/',
                'Sec-Ch-Ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"', // Adjust if your browser differs
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"', // Adjust based on your OS
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Gpc': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', // Adjust if your user agent differs
                'X-Requested-With': 'XMLHttpRequest'
            }
        });

        const html = response.data;
        const $ = cheerio.load(html);

        const caseDetails = {};
        $('table.case_details_table tr').each((index, element) => {
            const label = $(element).find('td:nth-child(1) label, td:nth-child(1) strong').text().replace(/\s+/g, ' ').trim().replace(':', '');
            const value = $(element).find('td:nth-child(2) label, td:nth-child(2) strong').text().replace(/\s+/g, ' ').trim();

            if (label && value) {
                if (label.includes("Filing Number")) {
                    caseDetails.filingNumber = value;
                } else if (label.includes("Filing Date")) {
                    caseDetails.filingDate = value;
                } else if (label.includes("Registration Number")) {
                    caseDetails.registrationNumber = value;
                } else if (label.includes("Registration Date")) {
                    caseDetails.registrationDate = value;
                }
            }
            // Handle the CNR Number row which spans 3 columns for its value
            const cnrLabel = $(element).find('td:nth-child(1) strong').text().replace(/\s+/g, ' ').trim();
            if (cnrLabel.includes("CNR Number")) {
                const cnrValue = $(element).find('td:nth-child(2) strong').text().replace(/\s+/g, ' ').trim();
                if (cnrValue) {
                    caseDetails.cnrNumber = cnrValue;
                }
            }
        });


        const caseStatus = {};
        $('table.table_r.table.text-left tr').each((index, element) => {
            const label = $(element).find('td:nth-child(1) strong').text().replace(/\s+/g, ' ').trim().replace(':', '');
            const value = $(element).find('td:nth-child(2) strong').text().replace(/\s+/g, ' ').trim();
            if (label && value) {
                if (label.includes("First Hearing Date")) {
                    caseStatus.firstHearingDate = value;
                } else if (label.includes("Next Hearing Date")) {
                    caseStatus.nextHearingDate = value;
                } else if (label.includes("Stage of Case")) {
                    caseStatus.stageOfCase = value;
                } else if (label.includes("Coram")) {
                    caseStatus.coram = value;
                } else if (label.includes("Bench Type")) {
                    caseStatus.benchType = value;
                } else if (label.includes("Judicial Branch")) {
                    caseStatus.judicialBranch = value;
                } else if (label.includes("State")) {
                    caseStatus.state = value;
                } else if (label.includes("District")) {
                    caseStatus.district = value;
                } else if (label.includes("Not Before Me")) {
                    caseStatus.notBeforeMe = value;
                }
            }
        });

        const petitioner = {};
        const petitionerText = $('.Petitioner_Advocate_table').text().trim();
        if (petitionerText) {
            const lines = petitionerText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
            if (lines.length > 0) {
                petitioner.name = lines[0].replace(/^\d+\)\s*/, ''); // Remove "1)"
                if (lines.length > 1) {
                    petitioner.advocate = lines[1].replace(/Advocate-\s*/, '');
                }
            }
        }

        const respondent = {};
        const respondentText = $('.Respondent_Advocate_table').text().trim();
        if (respondentText) {
            const lines = respondentText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
            if (lines.length > 0) {
                respondent.name = lines[0].replace(/^\d+\)\s*/, ''); // Remove "1)"
                if (lines.length > 1) {
                    respondent.advocate = lines[1].replace(/Advocate -\s*/, '');
                }
            }
        }


        const acts = [];
        $('#act_table tr').slice(1).each((index, element) => { // Skip header row
            const act = $(element).find('td:nth-child(1)').text().trim();
            const section = $(element).find('td:nth-child(2)').text().trim();
            if (act || section) {
                acts.push({ act, section });
            }
        });

        const categoryDetails = {};
        $('#subject_table tr').each((index, element) => {
            const label = $(element).find('td:nth-child(1) b').text().trim();
            const value = $(element).find('td:nth-child(2)').text().trim();
            if (label && value) {
                if (label.includes("Category")) {
                    categoryDetails.category = value;
                } else if (label.includes("Sub Category")) {
                    categoryDetails.subCategory = value;
                }
            }
        });

        const trialCourtInformation = {};
        const lowerCourtText = $('.Lower_court_table').text().trim();
        if (lowerCourtText) {
            const lines = lowerCourtText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
            lines.forEach(line => {
                if (line.includes("Court Number and Name")) {
                    trialCourtInformation.courtNumberAndName = line.split(':')[1]?.trim();
                } else if (line.includes("Case Number and Year")) {
                    trialCourtInformation.caseNumberAndYear = line.split(':')[1]?.trim();
                } else if (line.includes("Case Decision Date")) {
                    trialCourtInformation.caseDecisionDate = line.split(':')[1]?.trim();
                } else if (line.includes("State")) {
                    trialCourtInformation.state = line.split(':')[1]?.trim();
                } else if (line.includes("District")) {
                    trialCourtInformation.district = line.split(':')[1]?.trim();
                }
            });
        }

        const iaDetails = [];
        $('table.IAheading tr').slice(1).each((index, element) => { // Skip header row
            const iaNumber = $(element).find('td:nth-child(1)').text().replace('//', '').replace('Classification :', '').trim();
            const party = $(element).find('td:nth-child(2)').text().trim();
            const dateOfFiling = $(element).find('td:nth-child(3)').text().trim();
            const nextDate = $(element).find('td:nth-child(4)').text().trim();
            const iaStatus = $(element).find('td:nth-child(5)').text().trim();
            if (iaNumber || party || dateOfFiling || nextDate || iaStatus) {
                iaDetails.push({ iaNumber, party, dateOfFiling, nextDate, iaStatus });
            }
        });

        const linkedCases = [];
        $('table.linkedCase tr').slice(1).each((index, element) => { // Skip header row
            const filingNumber = $(element).find('td:nth-child(1)').text().trim();
            const caseNumber = $(element).find('td:nth-child(2)').text().trim();
            if (filingNumber || caseNumber) {
                linkedCases.push({ filingNumber, caseNumber });
            }
        });

        const firDetails = {};
        const firText = $('.FIR_details_table').text().trim();
        if (firText) {
            const lines = firText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
            lines.forEach(line => {
                if (line.includes("State")) {
                    firDetails.state = line.split(':')[1]?.trim();
                } else if (line.includes("District")) {
                    firDetails.district = line.split(':')[1]?.trim();
                } else if (line.includes("Police Station")) {
                    firDetails.policeStation = line.split(':')[1]?.trim();
                } else if (line.includes("FIR Number")) {
                    firDetails.firNumber = line.split(':')[1]?.trim();
                } else if (line.includes("Year")) {
                    firDetails.year = line.split(':')[1]?.trim();
                }
            });
        }

        const historyOfCaseHearing = [];
        $('table.history_table tr').slice(1).each((index, element) => { // Skip header row
            const causeListType = $(element).find('td:nth-child(1)').text().trim();
            const judge = $(element).find('td:nth-child(2)').text().trim();
            // The businessOnDate is within an <a> tag, get text from the <a> tag
            const businessOnDate = $(element).find('td:nth-child(3) a').text().trim() || $(element).find('td:nth-child(3)').text().trim();
            const hearingDate = $(element).find('td:nth-child(4)').text().trim();
            const purposeOfHearing = $(element).find('td:nth-child(5)').text().trim();

            if (causeListType || judge || businessOnDate || hearingDate || purposeOfHearing) {
                historyOfCaseHearing.push({
                    causeListType,
                    judge,
                    businessOnDate,
                    hearingDate,
                    purposeOfHearing
                });
            }
        });

        res.json({
            caseDetails,
            caseStatus,
            petitioner,
            respondent,
            acts,
            categoryDetails,
            trialCourtInformation,
            iaDetails,
            linkedCases,
            firDetails,
            historyOfCaseHearing
        });

    } catch (error) {
        console.error('Error fetching case details:', error);
        res.status(500).json({ error: 'Failed to fetch case details', details: error.message });
    }
});


app.get('/', (req, res) => {
    res.status(200).send('High Court Scraper API is running!');
});

app.listen(port, () => {
    console.log(`[${new Date().toISOString()}] High Court Scraper API listening at http://localhost:${port}`);
    console.warn(`[${new Date().toISOString()}] NOTE: This API makes direct requests to eCourts. If you encounter 'socket hang up' or other blocking issues, consider using a proxy service like ScraperAPI.`);
});