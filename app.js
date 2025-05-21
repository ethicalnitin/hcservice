require('dotenv').config(); // Load environment variables (e.g., PORT)
const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const cors = require('cors'); // For Cross-Origin Resource Sharing

const app = express();
const port = process.env.PORT || 3000; // Use PORT from .env or default to 3000

// --- Middleware Setup ---
app.use(cors({
    origin: 'https://verdant-cucurucho-13134b.netlify.app', // IMPORTANT: Replace with your actual frontend URL in production
    credentials: true, // Allow cookies to be sent with requests
    methods: ['GET', 'POST', 'OPTIONS'], // Explicitly allow methods
    allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept', 'Cookie'] // Allow necessary headers
}));
app.use(express.json()); // To parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // To parse URL-encoded request bodies

// --- Global Request Logger ---
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`\n[${timestamp}] --- Incoming API Request ---`);
    console.log(`[${timestamp}] Method: ${req.method}, Path: ${req.originalUrl}`);
    console.log(`[${timestamp}] Request Body:`, req.body);
    next();
});

// --- Helper Functions ---

/**
 * Parses 'Set-Cookie' headers from an Axios response into a plain object,
 * prioritizing JSESSIONID for '/hcservices' path and HCSERVICES_SESSID.
 * @param {string[]} setCookieHeaders - Array of 'Set-Cookie' strings from response headers.
 * @returns {Object} A plain object of cookie names and values.
 */
function parseSetCookieHeaders(setCookieHeaders) {
    const cookies = {};
    let jsessionHcservicesValue = null; // To hold the specific JSESSION for /hcservices

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
                        jsessionHcservicesValue = value; // Capture the specific JSESSION
                    }
                    // We still store other JSESSIONs if they exist, but prioritize the /hcservices one for the final string
                    cookies[name] = value;
                } else {
                    cookies[name] = value;
                }
            }
        });
    }

    // If we found a specific JSESSION for /hcservices, ensure it's the one that sticks
    if (jsessionHcservicesValue) {
        cookies['JSESSIONID'] = jsessionHcservicesValue; // Use JSESSIONID as the canonical name
        cookies['JSESSION'] = jsessionHcservicesValue; // Also set JSESSION for consistency
    }

    return cookies;
}

/**
 * Gets a consistent session ID from a parsed cookie object.
 * Prioritizes JSESSIONID, then HCSERVICES_SESSID.
 * @param {Object} cookies - Parsed cookie object.
 * @returns {string|null} The session ID.
 */
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

// --- API Routes ---

// Route for High Court Captcha Image
app.post('/api/captcha/highcourt', async (req, res) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] Handling High Court Captcha request.`);

    const captchaUrl = 'https://hcservices.ecourts.gov.in/hcservices/securimage/securimage_show.php?135=null'; // Cache-buster is usually dynamic

    try {
        const axiosConfig = {
            responseType: 'arraybuffer', // Crucial for image data
            headers: {
                // Mimic browser headers for the captcha request
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br', // Removed 'zstd' for broader compatibility
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': 'https://hcservices.ecourts.gov.in/hcservices/',
                'Sec-Fetch-Dest': 'image',
                'Sec-Fetch-Mode': 'no-cors',
                'Sec-Fetch-Site': 'same-origin',
                'Priority': 'u=1, i', // Included from your original curl
            },
            timeout: 15000, // 15 seconds timeout
            validateStatus: function (status) {
                return status >= 200 && status < 300 || status === 302; // Allow 302 redirects
            }
        };

        const response = await axios.get(captchaUrl, axiosConfig);

        // Handle potential redirects manually if axios.get doesn't automatically follow all
        if (response.status === 302 && response.headers.location) {
             console.log(`[${timestamp}] Received 302 redirect for captcha. Following to: ${response.headers.location}`);
             const redirectUrl = response.headers.location;
             // Re-fetch with the new location and original headers
             response = await axios.get(redirectUrl, axiosConfig);
         }

        const captchaImageBase64 = Buffer.from(response.data).toString('base64');
        const contentType = response.headers['content-type'] || 'image/png';

        // Parse Set-Cookie headers from the captcha response
        const setCookieHeaders = response.headers['set-cookie'];
        const parsedCookies = parseSetCookieHeaders(setCookieHeaders);
        const sessionId = getSessionIdFromCookies(parsedCookies);

        console.log(`[${timestamp}] Captcha fetched. Image size: ${response.data.length} bytes.`);
        console.log(`[${timestamp}] Captcha response cookies (parsed):`, parsedCookies);
        console.log(`[${timestamp}] Captcha response session ID: ${sessionId}`);

        res.json({
            captchaImageBase64: `data:${contentType};base64,${captchaImageBase64}`,
            cookies: parsedCookies, // Send parsed object to frontend
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

// Route for High Court Case Verification
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
        // REMOVED highCourtSelectedBench as it's not in the original curl
        cookies: frontendCookiesObject, // Expecting a cookies OBJECT from frontend
        sessionId: frontendSessionId // Optional, for logging/response
    } = req.body;

    console.log(`[${timestamp}] Received parameters:`);
    console.log(`  - Captcha: ${captcha}`);
    console.log(`  - Cookies Object from Frontend:`, frontendCookiesObject);
    console.log(`  - Session ID from Frontend (if provided): ${frontendSessionId}`);

    // Reconstruct the cookie string from the object received from the frontend.
    // This ensures the latest cookies from the captcha fetch are used.
    const cookieHeaderStringForExternalRequest = Object.entries(frontendCookiesObject || {})
        .map(([key, value]) => `${key}=${value}`)
        .join('; ');

    console.log(`[${timestamp}] Formatted Cookie header string for external request: "${cookieHeaderStringForExternalRequest}"`);

    // --- Input Validation ---
    if (!captcha || !petres_name || !rgyear || !caseStatusSearchType || !f ||
        !court_code || !state_code || !court_complex_code || !cookieHeaderStringForExternalRequest) { // highCourtSelectedBench removed from validation
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

    // --- Construct Payload for eCourts ---
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
        appFlag: 'web' // This was also not in the original curl, but often implied. Keep it for now.
    });
    console.log(`[${timestamp}] Constructed payload for eCourts: "${payload}"`);

    const caseVerificationUrl = 'https://hcservices.ecourts.gov.in/hcservices/cases_qry/index_qry.php';

    // --- Headers for External Request to eCourts ---
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
        'Cookie': cookieHeaderStringForExternalRequest, // Use the carefully constructed cookie string
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Content-Length': Buffer.byteLength(payload).toString()
    };
    console.log(`[${timestamp}] Headers for external request:`, headersToForward);

    try {
        const response = await axios.post(
            caseVerificationUrl,
            payload,
            { headers: headersToForward, timeout: 30000 } // 30 seconds timeout
        );

        console.log(`[${timestamp}] Received response from eCourts. Status: ${response.status}`);
        console.log(`[${timestamp}] Response Headers from eCourts:`, response.headers);

        let govData = response.data;
        console.log(`[${timestamp}] Raw response data from eCourts (first 500 chars): ${String(govData).substring(0, 500)}...`);

        // Attempt to parse if it's a string that looks like JSON
        if (typeof govData === 'string') {
            try {
                govData = JSON.parse(govData);
                console.log(`[${timestamp}] Successfully parsed main response data as JSON.`);
            } catch (jsonErr) {
                console.warn(`[${timestamp}] WARN: Main response data is a string but not valid JSON, leaving as string. Error: ${jsonErr.message}`);
            }
        }

        // Handle nested 'con' array parsing if it's a string (specific to eCourts response format)
        // This part needs to be robust as 'con' might not always be a string or array of strings
        if (govData && Array.isArray(govData.con) && govData.con.length > 0 && typeof govData.con[0] === 'string') {
            console.log(`[${timestamp}] Attempting to parse govData.con[0] as JSON...`);
            try {
                govData.con[0] = JSON.parse(govData.con[0]); // Parse the string inside the array
                console.log(`[${timestamp}] Successfully parsed govData.con[0] as JSON.`);
            } catch (err) {
                console.error(`[${timestamp}] ERROR: Error parsing govData.con[0]: ${err.message}`);
            }
        } else if (govData && typeof govData.con === 'string') { // If 'con' itself is a string
            console.log(`[${timestamp}] Attempting to parse govData.con as JSON...`);
            try {
                govData.con = JSON.parse(govData.con);
                console.log(`[${timestamp}] Successfully parsed govData.con as JSON.`);
            } catch (err) {
                console.error(`[${timestamp}] ERROR: Error parsing govData.con: ${err.message}`);
            }
        }


        // Capture and send back any new/updated cookies from the verification response
        const newSetCookieHeaders = response.headers['set-cookie'];
        const updatedCookiesForFrontend = parseSetCookieHeaders(newSetCookieHeaders);
        const finalSessionId = getSessionIdFromCookies(updatedCookiesForFrontend) || frontendSessionId;


        console.log(`[${timestamp}] Final processed data to send to frontend:`, govData);
        console.log(`[${timestamp}] New/Updated cookies to send to frontend:`, updatedCookiesForFrontend);
        console.log(`[${timestamp}] Final Session ID for frontend:`, finalSessionId);


        res.json({
            sessionID: finalSessionId,
            data: govData,
            cookies: updatedCookiesForFrontend // Send parsed object to frontend
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


// --- Health Check / Root Route ---
app.get('/', (req, res) => {
    res.status(200).send('High Court Scraper API is running!');
});

// --- Start the Server ---
app.listen(port, () => {
    console.log(`[${new Date().toISOString()}] High Court Scraper API listening at http://localhost:${port}`);
    console.warn(`[${new Date().toISOString()}] NOTE: This API makes direct requests to eCourts. If you encounter 'socket hang up' or other blocking issues, consider using a proxy service like ScraperAPI.`);
});