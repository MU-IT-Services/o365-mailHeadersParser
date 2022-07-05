// ----------------------------------------------------------------------------
// Header Parsing Functions & Constants
// ----------------------------------------------------------------------------
// Functions for parsing headers, and the constants needed to do that parsing.
// Nothing in this file should have any dependency on the UI, it should all be
// able to stand alone so it could be broken out into its own project later if
// needed.

//
// === JSDoc Type Defs ========================================================
//

/**
 * The unique ID  for a header, formed by forcing the header to lower case and
 * replacing dashes with underscores.
 * @typedef {string} HeaderID
 */

/**
 * An object representing a mail header.
 * @typedef {Object} HeaderObject
 * @property {string} name - The header name as it appeared in the email source.
 * @property {string} value - The header's value.
 */

/**
 * An object representing the canonical value of a header, i.e. the one header
 * by that name that is operative in a given parse direction.
 * @typedef {Object} CanonicalHeaderObject
 * @property {string} name - The header's name according to the RFCs.
 * @property {string} value - The header's canonical value.
 * @property {string[]} [values] - An optional array of the original values
 *   when there are multiple values found for the header.
 * @property {string} [info=''] — Optional additional information about the
 *   header.
 * @property {string} [warning=''] - Optional warning text regarding the
 *   header.
 * @property {string} [error=''] - Optional error text regarding the
 *   header.
 * @property {boolean} [isMissing] - Optional flag to indicate the header is
 *   required but no value was found for it.
 */

/**
 * An object representing all the mail headers for an email.
 * @typedef {Object} HeaderSet
 * @property {HeaderObject[]} list - The headers in chronological order, i.e.
 *   from the bottom to the top of the headers section in the email source.
 * @property {HeaderObject[]} listAsReceived - The headers in the order they
 *   appear in the headers section of the email source.
 * @property {<HeaderID, HeaderObject[]>} byHeaderID - Arrays of instances of
 *   headers (ordered from bottom to top), indexed by header ID.
 * @property {string} customPrefix - the prefix for headers to be considered
 *   custom.
 * @property {HeaderObject[]} listMatchingCustomPrefix - The headers that
 *   matched the custom prefix ordered from bottom to top.
 * @property {('inbound' | 'outbound')} [parsedirection=''] - The direction the
 *   mail is to be considered moving in, either 'inbound' to process the
 *   headers from the receiver's POV, or 'outbound' to process from the
 *   sender's POV.
 * @property {Object} canonicalByID - Any canonical headers found while
 *   parsing indexed by their ID.
 * @property {string[]} warnings - Validation warnings as strings.
 * @property {Object} securityReport — The aggregated results from parsing the
 *   Microsoft spam/security headers. TO DO - document this data structure!
 */

//
// === Data Definition Constants ===
//

/**
 * All the header names considered to be related to mail addressing.
 * 
 * @type {string[]}
 */
 const ADDRESSING_HEADERS = [
    'Date',
    'Subject',
    'To',
    'From',
    'Reply-To',
    'Return-Path',
    'Delivered-To',
    'Message-ID',
    'X-MS-Exchange-Organization-Network-Message-Id'
];

/**
 * A lookup of the header names to be marked as addressing-related.
 * 
 * @type {object.<string, boolean>}
 */
const ADDRESSING_HEADERS_LOOKUP = {};
for(const header of ADDRESSING_HEADERS){
    ADDRESSING_HEADERS_LOOKUP[header] = true;
    ADDRESSING_HEADERS_LOOKUP[header.toLowerCase()] = true;
}

/**
 * All the header namess considered to be related to mail routing.
 * 
 * @type {string[]}
 */
 const ROUTING_HEADERS = [
    'Received'
];

/**
 * A lookup of the header names to be marked as routing-related.
 * 
 * @type {object.<string, boolean>}
 */
const ROUTING_HEADERS_LOOKUP = {};
for(const header of ROUTING_HEADERS) {
    ROUTING_HEADERS_LOOKUP[header] = true;
    ROUTING_HEADERS_LOOKUP[header.toLowerCase()] = true;
}

/**
 * All the header names considered to be related to security/spam filtering.
 * 
 * @type {string[]}
 */
 const SECURITY_HEADERS = [
    'Authentication-Results',
    'X-Forefront-Antispam-Report',
    'X-Microsoft-Antispam',
    'Received-SPF',
    'DKIM-Signature',
    'Authentication-Results-Original'
];

/**
 * A lookup of the header names to be marked as security headers.
 * 
 * @type {object.<string, boolean>}
 */
const SECURITY_HEADERS_LOOKUP = {};
for(const header of SECURITY_HEADERS){
    SECURITY_HEADERS_LOOKUP[header] = true;
    SECURITY_HEADERS_LOOKUP[header.toLocaleLowerCase()] = true;
}

/**
 * A lookup of mail categorisation codes, mapping their abbreviations in the
 * header to their meanings. These are the codes used in the `CAT` field of the
 * `X-Forefront-Antispam-Report` header.
 * 
 * @type {object<string, string>}
 */
const MAIL_CATEGORISATION_CODES = {
    BULK: 'bulk mail',
    DIMP: 'domain impersonation',
    GIMP: 'mailbox intelligence-derived assumed impersonation',
    HPHSH: 'high-confidence phishing',
    HPHISH: 'high-confidence phishing',
    HSPM: 'high confidence spam',
    MALW: 'malware',
    PHSH: 'phishing',
    SPM: 'spam',
    SPOOF: 'spoofing',
    UIMP: 'user impersonation',
    AMP: 'anti-malware',
    SAP: 'safe attachments',
    OSPM: 'out-bound spam'
};

/**
 * A lookup of the spam filter action codes. These are the codes used in the
 * `SFV` field of the `X-Forefront-Antispam-Report` header.
 * 
 * @type {object<string, string>}
 */
const SPAM_FILTER_ACTION_CODES = {
    BLK: 'marked as bulk mail',
    NSPM: 'marked as not spam',
    SFE: "scan skipped because sender on recipient's safe senders list",
    SKA: 'scan skipped due to allow-list',
    SKB: 'scan skipped due to block-list',
    SKB: 'scan skipped because internal email',
    SKN: 'scan skipped because marked as not-spam by mail rule',
    SKQ: 'message released from quarantine',
    SKS: 'scan skipped because already marked as spam by mail rule',
    SPM: 'marked as spam'
};

//
// === Utility Functions ===
//

/**
 * Generate an empty header set object.
 * 
 * @returns {HeaderSet}
 */
 function generateBlankHeaderSet(){
    return {
        list: [],
        listAsReceived: [],
        byHeaderID: {},
        customPrefix: '',
        listMatchingCustomPrefix: [],
        parsedirection: '',
        canonicalByID: {},
        warnings: [],
        securityReport: {}
    };
}

/**
 * Check if a given value is a valid header name.
 * 
 * @param {*} val - The value to check.
 * @returns {boolean}
 */
function isHeaderName(val){
    if(typeof val !== 'string') return false;
    return val.match(/^[-a-z0-9]+$/i) ? true : false;
}

/**
 * Check if a given value is a valid header object.
 * 
 * @param {*} val - The value to check.
 * @returns {boolean}
 */
function isHeaderObject(val){
    if(typeof val !== 'object') return  false;
    if(!isHeaderName(val.name)) return false;
    if(typeof val.value !== 'string') return false;
    return true;
}

/**
 * Check if a given value is a header ID.
 * 
 * @param {*} val - The value to check.
 * @returns {boolean}
 */
function isHeaderID(val){
    if(typeof val !== 'string') return false;
    return val.match(/^a-z0-9_$/) ? true : false;
}

/**
 * Convert a header name to a header ID.
 * 
 * @param {string} headerName
 * @returns {HeaderID}
 * @throws {TypeError} A Type Error is thrown if the header name is not passed
 * or is not a string.
 * @throws {RangeError} A Range Error is thrown if a string is passed that's
 * not a valid header name.
 */
function headerNameToID(headerName){
    if(typeof headerName !== 'string'){
        throw new TypeError('header name is required and must be a string');
    }
    if(!isHeaderName(headerName)){
        throw new RangeError('invalid header name, can only contain letters, numbers, and dashes');
    }
    let ans = headerName.toLowerCase(); // start by lowercasing the name
    ans = ans.replaceAll('-', '_'); // replace dashes with undersores
    return ans;
}

/**
 * Clone a header object.
 * 
 * Naively creates a new object and copies the `name` and `value` attributes to
 * it.
 * 
 * @param {HeaderObject} headerObject - The header object to clone.
 * @returns {HeaderObject}
 * @throws {TypeError} A Type Error is thrown if the paramter is not an object.
 */
function cloneHeader(headerObject){
    if(!isHeaderObject(headerObject)) throw new TypeError('must pass a valid header object');
    return {
        name: headerObject.name,
        value: headerObject.value
    };
}

//
// === Microsoft-spcific Parsing Funtions =====================================
//

/**
 * Convert a compauth reason code into a meaning.
 * 
 * If invalid arguments are passed the string `'INVALID CODE'` and the code are returned.
 * 
 * @param {(string|number)} code - a three-digit number as a string or number.
 * @returns {string}
 */
 function compoundAuthenticationReason(code){
    code = String(code); // force the code to a string

    // validate the code
    const codeMatch = code.match(/^(\d)(\d\d)$/);
    if(!codeMatch) return `INVALID CODE: ${code}`
    const leadingDigit = codeMatch[1];
    const trailingDigits = codeMatch[2];

    // try find a real answer
    switch(leadingDigit){
        case '0':
            switch(trailingDigits){
                case '00':
                    return 'explicit failure - sending domain published DMARC/DKIM/SPF records';
                case '01':
                    return 'implicit failure - sending domain published no DMARC/DKIM/SPF records, or non-enforcing records';
                case '02':
                    return 'enforced failure - mail rule in place to enforce DMARC/DKIM/SPF even if the records are non-enforcing';
                case '10':
                    return 'exempted failure - the message failed DMARC but the domain is on the allow-list';
            }
            return 'generic failure';
            break;
        case '1':
        case '7':
            return 'explicit pass';
        case '2':
            return 'implicit pass';
        case '3':
            return 'not checked';
        case '4':
        case '9':
            return 'skipped';
        case '6':
            'exempted failure - the message failed compauth, but the domain is on the allow-list';
    }

    // if all else fails, return unknown
    return `UNKNOWN CODE: ${code}`;
}

/**
 * Convert an SCL (Spam Confidence Level) to a human-friendly description.
 * 
 * @see {@link https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/spam-confidence-levels?view=o365-worldwide}
 * @param {number} scl 
 * @returns {string}
 */
function sclMeaning(scl = -2){ // force to an invalid value of none passed
    scl = parseInt(scl); // force to integer

    // deal with valid values
    if(scl === -1) return 'not scored';
    if(scl === 0 || scl === 1) return 'not spam';
    if(scl === 5 || scl === 6) return 'spam';
    if(scl === 9) return 'high-confidence spam';

    // if all else fails, return 'UNKNOWN'
    return 'UNKNOWN'
}

/**
 * Convert a BCL (Bulk Mail Confidence Level) to a human-friendly description.
 * 
 * @param {number} scl 
 * @returns {string}
 * @see {@link https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/bulk-complaint-level-values?view=o365-worldwide}
 */
 function bclMeaning(bcl = -2){ // force to an invalid value of none passed
    bcl = parseInt(bcl); // force to integer

    // deal with valid values
    if(bcl === 0) return 'not from bulk mail sender';
    if(bcl <= 3) return 'from bulk mail sender with few user complaints';
    if(bcl <= 7) return 'from bulk mail sender with some user complaints';
    if(vcl <= 9) return 'from bulk mail sender with many user complaints';

    // if all else fails, return 'UNKNOWN'
    return 'UNKNOWN'
}

/**
 * Parse an authentication results header.
 * 
 * @param {string} input 
 * @return {object} Returns an object of the form:
 * ```
 * {
 *   authenticationResultsHeaderSpecified: true,
 *   compoundAuthentication: {
 *     result: 'unknown',
 *     reasonCode: '000',
 *     reasonMeaning: 'UNKNOWN'
 *   },
 *   dkim: {
 *     result: 'unknown',
 *     details: 'no additional info'
 *   },
 *   dmarc: {
 *     result: 'unknown',
 *     action: 'unknown',
 *     details: 'no additional info'
 *   },
 *   spf: {
 *     result: 'unknown',
 *     details: 'no additional info'
 *   }
 * }
 * ```
 * @throws {TypeError} A Type Error is thrown if a string is not passed.
 * @throws {RangeError} A Range Error is thrown if an invalid string is passed.
 */
 function parseAuthResultHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');

    // sanitise the header value
    let headerVal = sanitiseMailHeader(input);

    // strip off the header name (if present)
    headerVal = headerVal.replace(/^Authentication-Results:[ ]/, '');

    // if the header has no value, return an empty object
    if(headerVal === '') return {};

    // initiaise the return value
    const ans = {
        authenticationResultsHeaderSpecified: true,
        compoundAuthentication: {
            result: 'unknown',
            reasonCode: '000',
            reasonMeaning: 'UNKNOWN'
        },
        dkim: {
            result: 'unknown',
            details: 'no additional info'
        },
        dmarc: {
            result: 'unknown',
            action: 'unknown',
            details: 'no additional info'
        },
        spf: {
            result: 'unknown',
            details: 'no additional info'
        }
    };

    // split the value on semi-colon to get the various parts
    const headerParts = headerVal.trim().split(/;[ ]?/);

    // process each part
    for(const headerPart of headerParts){
        // skip empty part caused by trailing ;
        if(headerPart === '') continue;

        // get the part name and act appropriatey
        const headerPartMatch = headerPart.match(/^(\w+)=(\w+)[ ]?(.*)$/);
        if(headerPartMatch){
            const partName = headerPartMatch[1];
            const partOutcome = headerPartMatch[2];
            let partDetails = headerPartMatch[3];

            switch(partName){
                case 'compauth':
                    // store the overall result and details
                    ans.compoundAuthentication.result = partOutcome;
                    ans.compoundAuthentication.details = headerPart;

                    // parse the remainder of the entry
                    const reasonMatch = partDetails.match(/\breason=(\d{3})\b/);
                    if(reasonMatch){
                        const reasonCode = reasonMatch[1];
                        ans.compoundAuthentication.reasonCode = reasonCode;
                        ans.compoundAuthentication.reasonMeaning = compoundAuthenticationReason(reasonCode);

                    }else{
                        console.warn('failed to parse compound authentication reason');
                    }
                    break;
                case 'dmarc':
                    // store the overall result
                    ans.dmarc.result = partOutcome;

                    // parse the action
                    const dmarcActionMatch = partDetails.match(/\baction=([\w\d]+)\b/);
                    if(dmarcActionMatch){
                        ans.dmarc.action = dmarcActionMatch[1];
                    }else{
                        console.warn('failed to parse dmarc details', partDetails);
                    }
                    ans.dmarc.details = partDetails;
                    break;
                case 'dkim':
                case 'spf':
                    // store the overall result
                    ans[partName].result = partOutcome;

                    // strip any brackets that completely wrap the description
                    partDetails = partDetails.trim().replace(/^[(](.+)[)]$/, '$1');

                    // store the details
                    if(partDetails) ans[partName].details = partDetails;

                    break;
                default:
                    console.debug('unexpected header part name', partName, headerPart);        
            }
        }else{
            console.debug('failed to parse authentiation result header part', headerPart);
        }
    }
    
    //return the result
    return ans;
}

/**
 * Parse an original authentication results header (pre-quarantine authentication result).
 * 
 * @param {string} input 
 * @return {object} Returns an object of the form:
 * ```
 * {
 *   OriginalAuthenticationResultsHeaderSpecified: true,
 *   originalAuthResult: 'unknown'
 * }
 * ```
 * @throws {TypeError} A Type Error is thrown if a string is not passed.
 * @throws {RangeError} A Range Error is thrown if an invalid string is passed.
 */
 function parseOriginalAuthResultHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');

    // sanitise the header value
    let headerVal = sanitiseMailHeader(input);

    // strip off the header name (if present)
    headerVal = headerVal.replace(/^Authentication-Results-Original:[ ]/, '');

    // if the header has no value, return an empty object
    if(headerVal === '') return {};

    // initiaise the return value
    const ans = {
        OriginalAuthenticationResultsHeaderSpecified: true,
        originalAuthResult: 'unknown'
    };

    // try extract the auth result
    const authResultMatch = headerVal.match(/\bauth=(\w+)\b/);
    if(authResultMatch){
        ans.originalAuthResult = authResultMatch[1];
    }else{
        console.debug('failed to parse original authentiation result header', headerVal);
    }
    
    //return the result
    return ans;
}

/**
 * Parse a sanitised Office365 Forefront Span Report Header.
 * 
 * @see sanitiseMailHeader
 * @param {string} input 
 * @returns {object} Returns a plain object of the form:
 * ```
 * {
 *   spamReportHeaderSpecified: true,
 *   messageCategorisation: 'NONE',
 *   sender: {
 *     countryCode: 'DE',
 *     smtpHeloString: 'some.fqdn',
 *     ip: '1.2.3.4',
 *     ipReputation: 'none',
 *     ipReverseDNS: 'some.fqdn'
 *   },
 *   spamScore: 1,
 *   spamFilterAction: 'none',
 *   spoofingDetected: 'none',
 *   flaggedDueToUserComplaints: false,
 *   releasedFromQuarantine: false
 * }
 * ```
 * @throws {TypeError} A Type Error is thrown if a string is not passed.
 * @throws {RangeError} A Range Error is thrown if an invalid string is passed.
 */
function parseForefrontSpamReportHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');

    // sanitise the header value
    let headerVal = sanitiseMailHeader(input);

    // strip off the header name (if present)
    headerVal = headerVal.replace(/^X-Forefront-Antispam-Report:[ ]/, '');

    // if the header has no value, return an empty object
    if(headerVal === '') return {};

    // break the header down into its parts
    const header = {};
    let headerFields = headerVal.split(/;[ ]?/);
    for(const field of headerFields){
        if(field === '') continue;
        const fieldMatch = field.match(/^(\w+):(.*)$/)
        if(fieldMatch){
            header[fieldMatch[1]] = fieldMatch[2];
        }else{
            console.debug('failed to parse field', field);
        }
    }

    // assemble the return value
    const ans = {
        spamReportHeaderSpecified: true,
        messageCategorisation: MAIL_CATEGORISATION_CODES[header.CAT] ? MAIL_CATEGORISATION_CODES[header.CAT] : header.CAT,
        sender: {
            countryCode: header.CTRY || 'UNKNOWN',
            smtpHeloString: header.H,
            ip: header.CIP || '',
            ipReputation: 'none',
            ipReverseDNS: header.PTR
        },
        spamScore: parseInt(header.SCL) || -1,
        spamFilterAction: SPAM_FILTER_ACTION_CODES[header.SFV] ? SPAM_FILTER_ACTION_CODES[header.SFV] : 'none',
        spoofingDetected: 'none',
        flaggedDueToUserComplaints: header.SRV == 'BULK' ? true : false,
        releasedFromQuarantine: header.SFV == 'SKQ' ? true : false
    };
    if(header.IPV === 'CAL'){
        ans.sender.ipReputation = 'allow-listed';
    }else if(header.IPV === 'NLI'){
        ans.sender.ipReputation = 'not on any reputation lists';
    }
    if(header.SFTY == '9.19'){
        ans.spoofingDetected = 'user'
    }else if(header.SFTY == '9.20'){
        ans.spoofingDetected = 'domain'
    }
    return ans;
}

/**
 * Parse a Microsoft Anti-Spam header.
 * 
 * @param {string} input 
 * @return {object} Returns an object of the form:
 * ```
 * {
 *   bulkMailReportHeaderSpecified: true,
 *   bulkMailScore: 1
 * }
 * ```
 * @throws {TypeError} A Type Error is thrown if a string is not passed.
 * @throws {RangeError} A Range Error is thrown if an invalid string is passed.
 */
function parseMicrosoftAntiSpamHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');

    // sanitise the header value
    let headerVal = sanitiseMailHeader(input);

    // strip off the header name (if present)
    headerVal = headerVal.replace(/^X-Microsoft-Antispam:[ ]/, '');

    // if the header has no value, return an empty object
    if(headerVal === '') return {};

    // extract the BCL and return
    const bclMatch = input.match(/BCL:(\d+)/);
    return {
        bulkMailReportHeaderSpecified: true,
        bulkMailScore: bclMatch ? parseInt(bclMatch[1]) : -1
    };
}

//
// === Generic Header Parsing Functions =======================================
//

/**
 * Sanitise a raw mail header.
 * 
 * This function:
 * 1. trims the string
 * 2. collapses all whate space down to a single space
 * 
 * @param {string} input 
 * @returns {string}
 * @throws {TypeError} A type error is thrown if something other than a string is passed.
 */
 function sanitiseMailHeader(input){
    if(typeof input !== 'string') throw new TypeError('requires a string');
    return input.replace(/[\s]+/g, ' ').trim();
}

/**
 * Check if something is a plausible mail header.
 * 
 * A header must be a single-line string that starts with a header name
 * followed by a colon.
 * 
 * @param {string} input
 * @returns {boolean}
 */
 function isValidHeader(input){
    // make sure we have a string
    if(typeof input !== 'string') return false;

    // make sure the string starts with the expected text
    if(!input.match(/^[-\w\d]+:/)) return false;

    // make sure the string is a single line
    if(input.split(/\r\n|\r|\n/).length !== 1) return false;

    // if we got here all is well, so return true
    return true;
}

/**
 * Parse the headers or the entire raw source of an email into a header set.
 * 
 * @param {string} source
 * @param {('inbound'|'outbound')} parseDirection
 * @param {string} [customHeadersPrefix]
 * @returns {HeaderSet}
 * @throws {TypeError} A Type Error is thrown on invalid args.
 */
 function parseSource(source, parseDirection, customHeadersPrefix = ''){
    if(typeof source !== 'string') throw new TypeError('must pass a string to parse');
    if(!(parseDirection == 'inbound' || parseDirection == 'outbound')) throw new TypeError("must pass a parse direction of 'inbound' or 'outbound'");
    if(typeof customHeadersPrefix !== 'string') throw new TypeError('if passed, the custom header prefix must be a string');
    
    // create an empty data structure and store the prefix
    const ans = generateBlankHeaderSet();
    ans.customPrefix = customHeadersPrefix;

    // clean the source string
    let rawHeaders = source.trim(); // start by removing any leading or trailing white space
    rawHeaders.replace(/\n\r|\r\n/g, '\n'); // replace windows line endings with plain \n

    // split the cleaned source into lines
    const headerLines = rawHeaders.split('\n');

    // strip away an leading empty lines
    while(headerLines > 0){
        if(headerLines[0].match(/^\s*$/)) headerLines.shift();
    }

    // loop over each line to parse out the headers
    const wipHeader = { name: '', value: '' };
    const storeWIPHeader = ()=>{
        if(wipHeader.name.length > 0){
            // store the finished header
            ans.listAsReceived.push({...wipHeader});

            // start a new WIP header
            wipHeader.name = '';
            wipHeader.value = '';
        }
    };
    while(headerLines.length > 0){
        // shift the first remaning line
        const l = headerLines.shift();

        // if we reach a blank line, stop, we're at the end of the headers and into the body
        if(l.match(/^\s*$/)){
            break;
        }

        // see if we're starting a new header (no leading spaces) or continuing one
        if(l.match(/^\w/)){
            // new header

            // store the previous header
            storeWIPHeader();

            // spit the header name from the value
            const headerMatch = l.match(/^([-\w\d]+):[ ]?(.*)/);
            if(headerMatch){
                if(isHeaderName(headerMatch[1])){
                    wipHeader.name = headerMatch[1];
                    wipHeader.value = headerMatch[2] || '';
                }else{
                    console.warn('skipping invalid header name', headerMatch[1]);    
                }
            }else{
                console.warn('failed to parse header line', l);
            }
        }else if(l.match(/^\s+/)){
            // continuing the previous header

            // append the line to the current header
            wipHeader.value += ' ' + l.trim();
        }else{
            console.warn('failed to interpret header line', l);
        }
    }
    // store the last header
    storeWIPHeader();

    // loop over the list to build out the rest of the data structure
    let customPrefixID = headerNameToID(customHeadersPrefix);
    for(const header of ans.listAsReceived){
        // prepend the header to the chronological list
        ans.list.unshift(cloneHeader(header));

        // store in the lookup by ID
        const headerID = headerNameToID(header.name);
        if(ans.byHeaderID[headerID]){
            ans.byHeaderID[headerID].unshift(cloneHeader(header));
        }else{
            ans.byHeaderID[headerID] = [cloneHeader(header)];
        }

        // if there is a custom prefix, check if the header matches it
        if(customHeadersPrefix){
            if(headerID.startsWith(customPrefixID)){
                ans.listMatchingCustomPrefix.unshift(cloneHeader(header));
            }
        }
    }

    // validate and store the canonical headers, and any warnings generated in the process
    const findHeaders = (n)=>{
        const res = ans.byHeaderID[headerNameToID(n)];
        return res ? res : [];
    }
    const optionalSingleHeader = (n)=>{
        const hList = findHeaders(n);
        const hID = headerNameToID(n);
        ans.canonicalByID[hID] = { name: n, value: '' };
        if(hList && hList.length){
            if(hList.length == 1){
                ans.canonicalByID[hID].value = hList[0].value;
            }else{
                ans.canonicalByID[hID].values = [];
                for(const h of hList){
                    ans.canonicalByID[hID].values.push(h.value);
                }
                ans.canonicalByID[hID].error = `${hList.length} ${n} headers found`;
                ans.warnings.push(`${hList.length} ${n} headers found, only one allowed`);
            }
        }
    };
    const requireExactlyOne = (n)=>{
        const hList = findHeaders(n);
        const hID = headerNameToID(n);
        optionalSingleHeader(n);
        if(!(hList && hList.length)){
            ans.canonicalByID[hID].error = `no ${n} header found`;
            ans.canonicalByID[hID].isMissing = true;
            ans.warnings.push(`missing ${n} header`);
        }
    };
    const takeOne = (n)=>{
        const hList = findHeaders(n);
        const hID = headerNameToID(n);
        ans.canonicalByID[hID] = { name: n, value: '' };
        if(hList && hList.length){
            if(hList.length == 1 || parseDirection == 'outbound'){
                ans.canonicalByID[hID].value = hList[0].value;
            }else{
                ans.canonicalByID[hID].value = hList[hList.length - 1].value;
            }
        }
    };
    
    // validate and store the basic canonical headers
    requireExactlyOne('From');
    requireExactlyOne('Subject');
    requireExactlyOne('Date');
    optionalSingleHeader('Reply-To');
    optionalSingleHeader('Return-Path');
    requireExactlyOne('To');
    optionalSingleHeader('Delivered-To');
    requireExactlyOne('Message-ID');

    // look for the appropriate Exchange-specific headers
    takeOne('X-MS-Exchange-Organization-Network-Message-Id');

    // look for the appropriate Microsoft-specific security headers
    takeOne('Authentication-Results');
    takeOne('Authentication-Results-Original');
    takeOne('X-Forefront-Antispam-Report');
    takeOne('X-Microsoft-Antispam');

    // generate the security report based on the Microsoft headers
    ans.securityReport = {
        ...parseAuthResultHeader(ans.canonicalByID.authentication_results.value),
        ...parseOriginalAuthResultHeader(ans.canonicalByID.authentication_results_original.value),
        ...parseForefrontSpamReportHeader(ans.canonicalByID.x_forefront_antispam_report.value),
        ...parseMicrosoftAntiSpamHeader(ans.canonicalByID.x_microsoft_antispam.value)
    };

    // return the assembled data structure
    return ans;
}