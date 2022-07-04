// ----------------------------------------------------------------------------
// Header Parsing Functions & Constants
// ----------------------------------------------------------------------------
// Functions for parsing headers, and the constants needed to do that parsing.
// Nothing in this file should have any dependency on the UI, it should all be
// able to stand alone so it could be broken out into its own project later if
// needed.

//
// === JSDoc Type Defs ===
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
 * @property {string} [info=''] — Optional additional information about the
 *   header.
 * @property {string} [warning=''] - Optional warning text regarding the
 *   header.
 * @property {boolean} [hasError] — Optional flag to indicate there is a
 *   problem with the header's value.
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
        warnings: []
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
// === Header Parsing Functions ===
//

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
    const requireExactlyOne = (n)=>{
        const hList = findHeaders(n);
        const hID = headerNameToID(n);
        ans.canonicalByID[hID] = { name: n, value: '' };
        if(hList && hList.length){
            if(hList.length == 1){
                ans.canonicalByID[hID].value = hList[0];
            }else{
                ans.canonicalByID[hID].value = JSON.stringify(hList);
                ans.canonicalByID[hID].warning = `${hList.length} ${n} headers found`;
                ans.canonicalByID[hID].hasError = true;
                ans.warnings.push(`${hList.length} ${n} headers found, only one allowed`);
            }
        }else{
            ans.canonicalByID[hID].warning = `no ${n} header found`;
            ans.canonicalByID[hID].hasError = true;
            ans.warnings.push(`missing ${n} header`);
        }
    };
    
    // validate and store the basic canonical headers
    requireExactlyOne('From');
    requireExactlyOne('Subject');
    requireExactlyOne('Date');

    // return the assembled data structure
    return ans;
}