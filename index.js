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
        listMatchingCustomPrefix: []
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
// === Header Processing Functions ===
//

/**
 * Parse the headers or the entire raw source of an email into a header set.
 * 
 * @param {string} source
 * @param {string} [customHeadersPrefix]
 * @returns {HeaderSet}
 * @throws {TypeError} A Type Error is thrown on invalid args.
 */
function parseSource(source, customHeadersPrefix = ''){
    if(typeof source !== 'string') throw new TypeError('must pass a string to parse');
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

    // return the assembled data structure
    return ans;
}

//
// === Global Variables ===
//

/**
 * The data structure that will hold the headers once they are loaded.
 * 
 * @type {HeaderSet}
 */
let DATA = generateBlankHeaderSet();

/**
 * A dictionary providing easy access to jQuery objects representing the
 * important UI elements.
 * 
 * This data structure is initialised in the document ready handler.
 * 
 * @type {Object}
 * @property {boolean} initialised
 * @property {Object} form - The form elements.
 * @property {jQuery} form.source - The text area for entering the message
 *   source or plain text headers.
 * @property {jQuery} form.customHeadersPrefix - The text box to enter the
 *   prefix for highlighting custom headers of interest.
 * @property {jQuery} form.parseButton — The button to process the input.
 * @property {Object} output — Output regions.
 * @property {Object} alerts - The div where output alerts should be appended.
 * @property {jQuery} basicsUL - The unordered list to inject the basics into.
 * @property {jQuery} securityAnalysisUL - The unordered list to inject the
 *   security analysis into.
 * @property {jQuery} customHeadersUL - The unordered list to inject the custom
 *   headers into.
 * @property {jQuery} securityReportDiv - The `div` containing the security
 *   report.
 * @property {jQuery} allHeadersUL - The unordered list the full list of headers
 *   should be injected into.
 */
const $UI = {
    initialised: false,
    form: {
        source: $(),
        customHeadersPrefix: $(),
        parseButton: $()
    },
    output: {
        basicsUL: $(),
        securityAnalysisUL: $(),
        customHeadersUL: $(),
        securityReportDiv: $()
    }
};

//
// === The Document ready handler ===
//
$.when( $.ready ).then(function() {
    $UI.form.source = $('#fullHeaders-ta');
    $UI.form.customHeadersPrefix = $('#customHeadersPrefix-tb');
    $UI.form.parseBtn = $('#process_btn');
    $UI.output.alerts = $('#parseAlerts_div');
    $UI.output.basicsUL = $('#basics-ul');
    $UI.output.securityAnalysisUL = $('#securityAnalysis-ul');
    $UI.output.customHeadersUL = $('#customHeaders-ul');
    $UI.output.securityReportDiv = $('#securityReport-div');
    $UI.output.allHeadersUL = $('#allHeaders-ul');
    $UI.initialised = true;

    // add input form validation
    $UI.form.source.on('input', validateInputForm);
    $UI.form.customHeadersPrefix.on('input', validateInputForm);
    validateInputForm();

    // add an event handler to the parse button
    $UI.form.parseBtn.click(()=>{
        // reset the loaded headers data structure
        DATA = generateBlankHeaderSet();

        // blank all the output areas
        $UI.output.alerts.empty();
        $UI.output.basicsUL.empty().append(generatePlaceholderLI());
        $UI.output.securityAnalysisUL.empty().append(generatePlaceholderLI());
        $UI.output.customHeadersUL.empty().append(generatePlaceholderLI());
        $UI.output.securityReportDiv.empty().append(generatePlaceholderAlert());
        $UI.output.allHeadersUL.empty().append(generatePlaceholderLI());

        // parse the source
        let newHeaders = {};
        try{
            newHeaders = parseSource($UI.form.source.val(), $UI.form.customHeadersPrefix.val());
            console.debug(`successfully parsed source, found ${DATA.list.length} header(s)`, DATA);
        }catch(err){
            showParseError('Failed to parse source 🙁');
            console.warn('failed to parse email source with error:', err);
            return false;
        }

        // sanity check the new headers
        if(newHeaders.list.length < 1){
            showParseError('No headers found!');
            return false;
        }

        // all is well, so save the new headers
        DATA = newHeaders;

        // genereate the security report
        const securityDetails = {
    //         ...(headers.authentication_results ? parseAuthResultHeader(headers.authentication_results.value) : {}),
    //         ...(headers.authentication_results_original ? parseOriginalAuthResultHeader(headers.authentication_results_original.value) : {}),
    //         ...(headers.x_forefront_antispam_report ? parseForefrontSpamReportHeader(headers.x_forefront_antispam_report.value) : {}),
    //         ...(headers.x_microsoft_antispam ? parseMicrosoftAntiSpamHeader(headers.x_microsoft_antispam.value) : {})
        };
        console.debug(securityDetails);

        // render the header lists
        renderAllHeaders();
        renderCustomHeaders();

    //     // render the full security report
    //     $securityReportDiv.empty();
    //     if(Object.keys(securityDetails).length > 0){
    //         const $securityReport = $('<pre>').addClass('json-container').append(prettyPrintJson.toHtml(securityDetails, {}));
    //         $securityReportDiv.append($securityReport);
    //     }else{
    //         $securityReportDiv.append($('<div>').addClass('alert alert-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> No Secrity/Spam Headers Found!'));
    //     }

    //     //
    //     // render the basics
    //     //
    //     $basicsUL.empty();
    //     const generateBasicsLI = (n, v)=>{
    //         const $header = $('<li class="list-group-item"><code class="header-name"></code>: <span class="font-monospace header-value"></span></li>');
    //         $('.header-name', $header).text(n);
    //         $('.header-value', $header).text(v);
    //         return $header;
    //     };
    //     $basicsUL.append(generateBasicsLI('Subject', headers.subject ? headers.subject.value : '').addClass('fw-bold'));
    //     $basicsUL.append(generateBasicsLI('Date', headers.date? headers.date.value : 'UNKNOWN'));
    //     //$basicsUL.append(generateBasicsLI('From', headers.from ? headers.from.value : 'UNKNOWN').addClass('fw-bold'));
    //     //if (headers['reply-to']) $basicsUL.append(generateBasicsLI('Reply To', headers['reply-to'].value));
    //     //if (headers['return-path']) $basicsUL.append(generateBasicsLI('Return Path', headers['return-path'].value));
    //     const $fromLI = $('<li class="list-group-item"><strong><code>From</code>: <span class="font-monospace from-header-value"></span></strong></li>');
    //     $('.from-header-value', $fromLI).text(headers.from ? headers.from.value : 'UNKNOWN');
    //     if (headers['reply-to']){
    //         if ((headers['reply-to'].value == headers.from.value)){
    //             const $replyTo = $('<small>').html('<i class="bi bi-plus-circle"></i> Reply To').addClass('badge bg-secondary');
    //             $fromLI.append(' ').append($replyTo);
    //         }else{
    //             const $replyTo = $('<small class="text-nowrap text-muted"><code>Reply-To</code>: <span class="font-monospace reply-to-header-value"></span></small>');
    //             $('.reply-to-header-value', $replyTo).text(headers['reply-to'].value);
    //             $fromLI.append(' ').append($replyTo);
    //         }
    //     }
    //     if (headers['return-path']){
    //         const $returnPath = $('<small class="text-nowrap text-muted"><code>Return-Path</code>: <span class="font-monospace return-path-header-value"></span></small>');
    //         $('.return-path-header-value', $returnPath).text(headers['return-path'].value);
    //         $fromLI.append(' ').append($returnPath);
    //     }
    //     $basicsUL.append($fromLI);
    //     const $toLI = $('<li class="list-group-item"><strong><code>To</code>: <span class="font-monospace to-header-value"></span></strong></li>');
    //     $('.to-header-value', $toLI).text(headers.to? headers.to.value : 'UNKNOWN');
    //     if (headers['delivered-to']){
    //         const $deliveredTo = $('<small class="text-muted">Also delivered to <span class="font-monospace delivered-to-header-value"></span></small>');
    //         $('.delivered-to-header-value', $deliveredTo).text(headers['delivered-to'].value);
    //         $toLI.append(' ').append($deliveredTo);
    //     } 
    //     $basicsUL.append($toLI);
    //     $basicsUL.append(generateBasicsLI('Message ID', headers['message-id']? headers['message-id'].value : 'UNKNOWN').addClass('fw-bold'));

    //     //
    //     // render the security summary
    //     //
    //     $securityAnalysisUL.empty();

    //     // a local function to render an info tooltip within the security analysis
    //     const appendInfo = ($li, info)=>{
    //         const $info = $('<i class="bi bi-info-circle-fill"></i>').attr('title', info);
    //         new bootstrap.Tooltip($info[0]);
    //         $li.append(' ').append($info);
    //     };

    //     // start with the authentication results header
    //     if(securityDetails.authenticationResultsHeaderSpecified){
    //         // start with compound auth
    //         const $compAuthLI = $('<li>').addClass('list-group-item').html('<strong>Compound Authentication:</strong> ');
    //         const appendCompauthReason = ($li)=>{
    //             if(securityDetails.compoundAuthentication.reasonCode !== '000'){
    //                 $info = $('<span>').addClass('text-muted').html(' <code class="code"></code> <span class="meaning"></span>');
    //                 $('.code', $info).text(securityDetails.compoundAuthentication.reasonCode);
    //                 $('.meaning', $info).text(securityDetails.compoundAuthentication.reasonMeaning);
    //                 $li.append($info);
    //             }
    //         };
    //         switch(securityDetails.compoundAuthentication.result){
    //             case 'pass':
    //             case 'softpass':
    //                 $compAuthLI.append($('<span>').addClass('badge bg-success').text(securityDetails.compoundAuthentication.result));
    //                 appendCompauthReason($compAuthLI);
    //                 break;
    //             case 'none':
    //                 $compAuthLI.append($('<span>').addClass('badge bg-warning').text('NOT PERFORMED'));
    //                 appendCompauthReason($compAuthLI);
    //                 break;
    //             case 'fail':
    //                 $compAuthLI.append($('<span>').addClass('badge bg-danger').text('FAIL'));
    //                 appendCompauthReason($compAuthLI);
    //                 break;
    //             case 'unknown':
    //                 $compAuthLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No Compound Auhentication details found in <code>Authentication-Results</code> header'));
    //                 break;
    //             default:
    //                 $compAuthLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.compoundAuthentication.result}</code>`));
    //         }
    //         $securityAnalysisUL.append($compAuthLI);

    //         // local function for adding details to SFP, DKIM, or DMARC
    //         const appendDetails = ($li, result)=>{
    //             $li.append('<br>').append($('<small>').addClass('text-muted font-monospace').text(result.details));
    //         };

    //         // add SPF
    //         const $spfLI = $('<li>').addClass('list-group-item').html('<strong>SPF Validation:</strong> ');
    //         switch(securityDetails.spf.result){
    //             case 'none':
    //                 $spfLI.append($('<span>').addClass('badge bg-secondary').text('no SPF record'));
    //                 appendDetails($spfLI, securityDetails.spf);
    //                 break;
    //             case 'pass':
    //                 $spfLI.append($('<span>').addClass('badge bg-success').text('pass'));
    //                 appendDetails($spfLI, securityDetails.spf);
    //                 break;
    //             case 'neutral':
    //                 $spfLI.append($('<span>').addClass('badge bg-primary').text('neutral'));
    //                 appendDetails($spfLI, securityDetails.spf);
    //                 break;
    //             case 'fail':
    //                 $spfLI.append($('<span>').addClass('badge bg-danger').text(securityDetails.spf.result));
    //                 appendDetails($spfLI, securityDetails.spf);
    //                 break;
    //             case 'softfail':
    //                 $spfLI.append($('<span>').addClass('badge bg-danger').text('soft fail'));
    //                 appendInfo($spfLI, 'sender denied but SPF record is permissive (~all), not enforcing (-all)');
    //                 appendDetails($spfLI, securityDetails.spf);
    //                 break;
    //             case 'temperror':
    //                 $spfLI.append($('<span>').addClass('badge bg-warning').text('temporary error'));
    //                 appendInfo($spfLI, 'SPF processing failed because of a temporary problem, usually a DNS lookup failure');
    //                 appendDetails($spfLI, securityDetails.spf);
    //                 break;
    //             case 'permerror':
    //                 $spfLI.append($('<span>').addClass('badge bg-danger').text('permanent error'));
    //                 appendInfo($spfLI, 'SPF processing failed because of a problem with the record, usally a syntax error in the record itself');
    //                 appendDetails($spfLI, securityDetails.spf);
    //                 break;
    //             case 'unknown':
    //                 $spfLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No SPF details found in <code>Authentication-Results</code> header'));
    //                 break;
    //             default:
    //                 $spfLI.append($('<strong>').addClass('text-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.spf.result}</code>'));
    //         }
    //         $securityAnalysisUL.append($spfLI);

    //         // add DKIM
    //         const $dkimLI = $('<li>').addClass('list-group-item').html('<strong>DKIM Validation:</strong> ');
    //         switch(securityDetails.dkim.result){
    //             case 'none':
    //                 $dkimLI.append($('<span>').addClass('badge bg-secondary').text('message not signed'));
    //                 break;
    //             case 'pass':
    //                 $dkimLI.append($('<span>').addClass('badge bg-success').text('pass'));
    //                 appendDetails($dkimLI, securityDetails.dkim);
    //                 break;
    //             case 'fail':
    //                 $dkimLI.append($('<span>').addClass('badge bg-danger').text(securityDetails.dkim.result));
    //                 appendDetails($dkimLI, securityDetails.dkim);
    //                 break;
    //             case 'unknown':
    //                 $dkimLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No DKIM details found in <code>Authentication-Results</code> header'));
    //                 break;
    //             default:
    //                 $dkimLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.dkim.result}</code>`));
    //         }
    //         $securityAnalysisUL.append($dkimLI);

    //         // add DMARC
    //         const $dmarcLI = $('<li>').addClass('list-group-item').html('<strong>DMARC Validation:</strong> ');
    //         switch(securityDetails.dmarc.result){
    //             case 'none':
    //                 $dmarcLI.append($('<span>').addClass('badge bg-secondary').text('no DMARC record'));
    //                 break;
    //             case 'pass':
    //                 $dmarcLI.append($('<span>').addClass('badge bg-success').text('pass'));
    //                 appendDetails($dmarcLI, securityDetails.dmarc);
    //                 break;
    //             case 'bestguesspass':
    //                 $dmarcLI.append($('<span>').addClass('badge bg-success').text('inferred pass'));
    //                 appendInfo($dmarcLI, 'There is no DMARC record for the domain, but if a typical record existed, it would have passed');
    //                 appendDetails($dmarcLI, securityDetails.dmarc);
    //                 break;
    //             case 'fail':
    //                 $dmarcLI.append($('<span>').addClass('badge bg-danger').text(securityDetails.dmarc.result));
    //                 appendDetails($dmarcLI, securityDetails.dmarc);
    //                 break;
    //             case 'temperror':
    //                 $dmarcLI.append($('<span>').addClass('badge bg-warning').text('temporary error'));
    //                 appendInfo($dmarcLI, 'DMARC processing failed because of a temporary problem, usually a DNS lookup failure');
    //                 appendDetails($dmarcLI, securityDetails.dmarc);
    //                 break;
    //             case 'permerror':
    //                 $dmarcLI.append($('<span>').addClass('badge bg-danger').text('permanent error'));
    //                 appendInfo($dmarcLI, "DMARC processing failed because of a problem retrieving or processing the DNS record. This usually happens when there is a syntax error in the record, or, when the domain name doesn't reslove on the public internet (e.g. cron on a host without a public DNS name).");
    //                 appendDetails($dmarcLI, securityDetails.dmarc);
    //                 break;
    //             case 'unknown':
    //                 $dmarcLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No DKIM details found in <code>Authentication-Results</code> header'));
    //                 break;
    //             default:
    //                 $dmarcLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.dmarc.result}</code>`));
    //         }
    //         $securityAnalysisUL.append($dmarcLI);
    //     }else{
    //         $securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>Authentication-Results</code> header found'));
    //     }

    //     // next the spam report header
    //     if(securityDetails.spamReportHeaderSpecified){
    //         // start with the spam score
    //         const $spamScoreLI = $('<li>').addClass('list-group-item').html('<strong>Spam Filter:</strong> ');
    //         const $scl = $('<span>').addClass('badge').html('SCL <span class="code font-monospace"></span> — <span class="meaning"></span>');
    //         const sclDesc = sclMeaning(securityDetails.spamScore);
    //         $('.code', $scl).text(securityDetails.spamScore);
    //         $('.meaning', $scl).text(sclDesc);
    //         switch(sclDesc){
    //             case 'not spam':
    //                 $scl.addClass('bg-success');
    //                 break;
    //             case 'spam':
    //             case 'high confidence spam':
    //                 $scl.addClass('bg-danger');
    //                 break;
    //              default:
    //                 $scl.addClass('bg-secondary');
    //         }
    //         $spamScoreLI.append($scl);
    //         if(securityDetails.spamFilterAction !== 'none'){
    //             $spamScoreLI.append(' ').append($('<span>').text(securityDetails.spamFilterAction));
    //         }
    //         $securityAnalysisUL.append($spamScoreLI);
            
    //         // finish with the quarantine info
    //         const $quarantineLI = $('<li>').addClass('list-group-item').html('<strong>Quarantine Details:</strong> ');
    //         const $quarantinedBadge = $('<span>').addClass('badge');
    //         if(securityDetails.releasedFromQuarantine){
    //             // the mail was relesed from quarantine
    //             $quarantinedBadge.text('Released from Quarantine').addClass('bg-warning');
    //         }else{
    //             // the mail was not quarantined
    //             $quarantinedBadge.text('Not Quarantined').addClass('bg-success');
    //         }
    //         $quarantineLI.append($quarantinedBadge);
    //         if(securityDetails.releasedFromQuarantine){
    //             if(securityDetails.OriginalAuthenticationResultsHeaderSpecified){
    //                 const $originalAuthResult = $('<span>').text(securityDetails.originalAuthResult).addClass('badge');
    //                 switch(securityDetails.originalAuthResult){
    //                     case 'fail':
    //                         $originalAuthResult.addClass('bg-error');
    //                         break;
    //                     case 'pass':
    //                         $originalAuthResult.addClass('bg-success');
    //                         break;
    //                     default:
    //                         $originalAuthResult.addClass('bg-danger');
    //                 }
    //                 $quarantineLI.append('<br>').append($('<small>').text('Pre-quarantine Authentication Result: ').addClass('text-muted').append($originalAuthResult));
    //             }else{
    //                 $quarantineLI.append('<br>').append($('<small>').text('No pre-quarantine authentication header found').addClass('text-muted fst-italic'));
    //             }
    //         }
    //         $securityAnalysisUL.append($quarantineLI);
    //     }else{
    //         $securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>X-Forefront-Antispam-Report</code> header found'));
    //     }

    //     // next the bulk mail header
    //     if(securityDetails.bulkMailReportHeaderSpecified){
    //         const $bulkMailScoreLI = $('<li>').addClass('list-group-item').html('<strong>Bulk Mail Filter:</strong> ');
    //         const $bcl = $('<span>').html('<span class="badge">BCL <span class="code font-monospace"></span></span> <span class="meaning text-muted"></span>');
    //         const bclDesc = bclMeaning(securityDetails.bulkMailScore);
    //         $('.code', $bcl).text(securityDetails.bulkMailScore);
    //         $('.meaning', $bcl).text(bclDesc);
    //         if(bclDesc === 'not from bulk mail sender' || bclDesc.includes('few user complaints')){
    //             $('.badge', $bcl).addClass('bg-success');
    //         }else if(bclDesc.includes('some user complaints')){
    //             $$('.badge', $bcl).addClass('bg-warning');
    //         }else if(bclDesc.includes('many user complaints')){
    //             $('.badge', $bcl).addClass('bg-danger');
    //         }else{
    //             $('.badge', $bcl).addClass('bg-secondary');
    //         }
    //         $bulkMailScoreLI.append($bcl);
    //         $securityAnalysisUL.append($bulkMailScoreLI);
    //     }else{
    //         $securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>X-Microsoft-Antispam</code> header found'));
    //     }

    //     // end with the details to submit the mail to Microsoft for review
    //     if(headers['x-ms-exchange-organization-network-message-id']){
    //         const $submitToMSLI = $('<li>').addClass('list-group-item list-group-item-info')
    //         $submitToMSLI.html(`<i class="bi bi-info-circle"></i> If this mail was mishandled by Micorosft's filters you can submit it for review using the Network Message ID <code>${headers['x-ms-exchange-organization-network-message-id'].value}</code>. <a href="https://security.microsoft.com/reportsubmission?viewid=admin" rel="nofollow" target="_blank" class="btn btn-outline-primary btn-sm">Submit to MS <i class="bi bi-box-arrow-up-right"></i></a>`);
    //         $securityAnalysisUL.append($submitToMSLI);
    //     }
    });

    // focus the source field
    $UI.form.source.focus();
});

//
// === UI functions ===
//

//
// -- UI Utility Functions --
//

/**
 * Generate a placeholder list item for when no headers have been parsed.
 * 
 * @returns {jQuery}
 */
function generatePlaceholderLI(){
    $ans = $('<li>').addClass('list-group-item list-group-item-warning');
    $ans.html('<i class="bi bi-exclamation-triangle-fill"></i> <strong>No Headers Processed Yet</strong> — use the form to enter headers or raw source for processing');
    return $ans;
}

/**
 * Generate a placeholder alert for when no headers have been parsed.
 * 
 * @returns {jQuery}
 */
 function generatePlaceholderAlert(){
    $ans = $('<div>').addClass('alert alert-warning mb-0');
    $ans.html('<i class="bi bi-exclamation-triangle-fill"></i> <strong>No Headers Processed Yet</strong> — use the form to enter headers or raw source for processing');
    return $ans;
}

/**
 * Output a parse error alert.
 * 
 * @param {string} errorText
 */
function showParseError(errorText){
    $alert = $('<div>').addClass('alert alert-danger').text(errorText);
    $alert.prepend('<i class="bi bi-exclamation-triangle-fill"></i> ');
    $UI.output.alerts.append($alert);
}

//
// -- Form Validation Functions --
//

/**
 * Validate the input form.
 * 
 * @return {boolean}
 */
 function validateInputForm(){
    // validate each input
    let numError = 0;
    let numMissingRequired = 0;
    if($UI.form.source.val().match(/\w/)){
        $UI.form.source.removeClass('is-invalid').addClass('is-valid');
    }else{
        numMissingRequired++;
        $UI.form.source.removeClass('is-valid');
        if($UI.form.source.val() !== ''){
            $UI.form.source.addClass('is-invalid');
            numError++;
        }
    }
    if($UI.form.customHeadersPrefix.val().length > 0){
        $UI.form.customHeadersPrefix.addClass('is-valid');
    }else{
        $UI.form.customHeadersPrefix.removeClass('is-valid');
    }
    
    // if we've no errors and no missing required fields, enable the button
    if(numError === 0 && numMissingRequired === 0){
        $UI.form.parseBtn.prop('disabled', false);
        return true;
    }

    // default to disabling and return false
    $UI.form.parseBtn.prop('disabled', true);
    return false;
}

//
// -- Rendering Functions --
//

/**
 * Render the  full list of headers.
 */
function renderAllHeaders(){
    // empty the header UL
    $UI.output.allHeadersUL.empty();

    // loop over all the loaded headers and append them to the UL
    for(const header of DATA.listAsReceived){
        const $header = $('<li class="list-group-item"><code class="header-name"></code><br><span class="font-monospace header-value"></span></li>');
        $('.header-name', $header).text(header.name);
        $('.header-value', $header).text(header.value);
        if(SECURITY_HEADERS_LOOKUP[header.name.toLowerCase()]){
            $header.addClass('bg-danger bg-opacity-10');
        }else if(ROUTING_HEADERS_LOOKUP[header.name.toLowerCase()]){
            $header.addClass('bg-warning bg-opacity-10');
        }else if(ADDRESSING_HEADERS_LOOKUP[header.name.toLowerCase()]){
            $header.addClass('bg-primary bg-opacity-10');
        }else if(DATA.customPrefix.length > 0 && header.name.toLowerCase().startsWith(DATA.customPrefix.toLowerCase())){
            $header.addClass('bg-success bg-opacity-10');
        }
        $UI.output.allHeadersUL.append($header);    
    }
}

/**
 * Render the highlighted custom headers, if any.
 */
function renderCustomHeaders(){
    // empty the list
    $UI.output.customHeadersUL.empty();
    if(DATA.customPrefix.length > 0){
             if(DATA.listMatchingCustomPrefix.length > 0){
                for(const header of DATA.listMatchingCustomPrefix){
                    const $header = $('<li class="list-group-item"><code class="header-name"></code><br><span class="font-monospace header-value"></span></li>');
                    $('.header-name', $header).text(header.name);
                    $('.header-value', $header).text(header.value);
                    $UI.output.customHeadersUL.append($header);
                }
             }else{
                 $UI.output.customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-warning').html(`<i class="bi bi-exclamation-triangle-fill"></i> found no headers pre-fixed with <code>${DATA.customPrefix}</code>`));
             }
    }else{
        $UI.output.customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-info').html('<strong><i class="bi bi-info-circle-fill"></i> No custom prefix specified</strong> — enter a prefix in the form to spotlight matching headers'));
    }
}

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