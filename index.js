// data

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
}

// Document ready handler
$.when( $.ready ).then(function() {
    const $fullHeadersTA = $('#fullHeaders-ta');
    const $extractBtn = $('button#extract_btn');
    const $authResultsHeaderTA = $('#authResultsHeader-ta');
    const $forefrontSpamReportTA = $('#forefrontSpamReport-ta');
    const $microsoftAntiSpamHeaderTA = $('#microsoftAntiSpamHeader-ta');
    const $parseBtn = $('button#parse_btn');

    // local function to validate the headers form
    const validateHeadersFn = ()=>{validateHeaderForm($authResultsHeaderTA, $forefrontSpamReportTA, $microsoftAntiSpamHeaderTA)};

    // add form validatoin to the header extraction form
    $fullHeadersTA.on('input', ()=>{
        if($fullHeadersTA.val().match(/\w/)){
            $fullHeadersTA.removeClass('is-invalid').addClass('is-valid');
            $extractBtn.prop('disabled', false);
        }else if($fullHeadersTA.val() === ''){
            $fullHeadersTA.removeClass('is-invalid', 'is-valid');
            $extractBtn.prop('disabled', true);
        }else{
            $fullHeadersTA.removeClass('is-valid').addClass('is-invalid');
            $extractBtn.prop('disabled', true);
        }
    }).trigger('input');

    // add an event handler to the extract button
    $extractBtn.click(()=>{
        // split the raw source into an array of lines
        let rawHeaders = $fullHeadersTA.val().trim();
        rawHeaders.replace(/\n\r|\r\n/g, '\n'); // replace windows line endings with plain \n
        const headerLines = rawHeaders.split('\n');

        // strip away an leading empty lines
        while(headerLines > 0){
            if(headerLines[0].match(/^\s*$/)) headerLines.shift();
        }
        if(headerLines.length === 0){
            window.alert('no hearders!');
            return false;
        }

        // extract all headers
        const headers = {};
        let currentHeader = '';
        while(headerLines.length > 0){
            // shift the first remaning line
            const l = headerLines.shift();

            // if we reach a blank line, stop, we're at the end of the headers and into the body
            if(l.match(/^\s*$/)){
                break;
            }

            // see if we're starting a new header (no leading spaces) or continuing one
            if(l.match(/^\w/)){
                // spit the header name from the value
                const headerMatch = l.match(/^([-\w\d]+):[ ]?(.*)/);
                if(headerMatch){
                    headers[headerMatch[1]] = headerMatch[2] || '';
                    currentHeader = headerMatch[1];
                }else{
                    console.warn('failed to parse header line', l);
                }
            }else if(l.match(/^\s+/)){
                // append the line to the current header
                headers[currentHeader] += l.trim();
            }else{
                console.warn('failed to interpret header line', l);
            }
        }

        // populate the relevant text areas and validate the form
        $authResultsHeaderTA.val('Authentication-Results: ' + headers['Authentication-Results']);
        $forefrontSpamReportTA.val('X-Forefront-Antispam-Report: ' + headers['X-Forefront-Antispam-Report']);
        $microsoftAntiSpamHeaderTA.val('X-Microsoft-Antispam: ' + headers['X-Microsoft-Antispam']);
        validateHeadersFn();
    });

    // add form validation to the header text areas
    $authResultsHeaderTA.on('input', validateHeadersFn);
    $forefrontSpamReportTA.on('input', validateHeadersFn);
    $microsoftAntiSpamHeaderTA.on('input', validateHeadersFn);
    validateHeadersFn();

    // add an event handler to the parse button
    $parseBtn.click(()=>{
        const messageDetails = {
            ...parseForefrontSpamReportHeader(sanitiseMailHeader($forefrontSpamReportTA.val()))
        };
        const $out = $('<pre>').text(JSON.stringify(messageDetails, null, 2));
        $('#output_div').empty().append($out);
    });
});

/**
 * Validate the forefront spam report header input box.
 * 
 * @param {jQuery} $authResultsHeaderTA - a jQuery object representing the
 * auth results header text area.
 * @param {jQuery} $authResulforefrontSpamReportTAtsHeaderTA - a jQuery object
 * representing the forefront spam report text area.
 * @param {jQuery} $microsoftAntiSpamHeaderTA - a jQuery object representing
 * the microsoft anti-spam header text area.
 * @return {boolean}
 */
 function validateHeaderForm($authResultsHeaderTA, $forefrontSpamReportTA, $microsoftAntiSpamHeaderTA){
    // make sure we were passed three jQuery objects
    for(const $textArea of [$authResultsHeaderTA, $forefrontSpamReportTA, $microsoftAntiSpamHeaderTA]){
        if(!$textArea instanceof $){
            console.warn('header form validation must be passed three jQuery objects');
            return false;
        }
    }

    // validate each text area
    let allOK = true;
    if(isValidAuthResultHeader(sanitiseMailHeader($authResultsHeaderTA.val()))){
        $authResultsHeaderTA.removeClass('is-invalid').addClass('is-valid');
    }else{
        $authResultsHeaderTA.removeClass('is-valid');
        if($authResultsHeaderTA.val() !== ''){
            $authResultsHeaderTA.addClass('is-invalid');
        }
        allOK = false;
    }
    if(isValidForefrontSpamReportHeader(sanitiseMailHeader($forefrontSpamReportTA.val()))){
        $forefrontSpamReportTA.removeClass('is-invalid').addClass('is-valid');
    }else{
        $forefrontSpamReportTA.removeClass('is-valid');
        if($forefrontSpamReportTA.val() !== ''){
            $forefrontSpamReportTA.addClass('is-invalid');
        }
        allOK = false;
    }
    if(isValidMicrosoftAntiSpamHeader(sanitiseMailHeader($microsoftAntiSpamHeaderTA.val()))){
        $microsoftAntiSpamHeaderTA.removeClass('is-invalid').addClass('is-valid');
    }else{
        $microsoftAntiSpamHeaderTA.removeClass('is-valid');
        if($microsoftAntiSpamHeaderTA.val() !== ''){
            $microsoftAntiSpamHeaderTA.addClass('is-invalid');
        }
        allOK = false;
    }
    
    // if none failed, enable the form and return true
    if(allOK){
        $authResultsHeaderTA.closest('form').find('button').prop('disabled', false);
        return true;
    }

    // default to disabling and return false
    $authResultsHeaderTA.closest('form').find('button').prop('disabled', true);
    return false;
}

/**
 * Validate the microsoft anti-spam header input box.
 * 
 * @param {jQuery} $textArea - a jQuery object representing the text area to validate
 * @return {boolean}
 */
 function validateAntiSpamTA($textArea){
    if(isValidSpamReportHeader(sanitiseMailHeader($textArea.val()))){
        $textArea.removeClass('is-invalid').addClass('is-valid');
        $textArea.closest('form').find('button').prop('disabled', false);
        return true;
    }
    $textArea.removeClass('is-valid').addClass('is-invalid');
    //$textArea.closest('form').find('button').prop('disabled', true);
    return false;
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
    return input.trim().replace(/[\s]+/g, ' ');
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
 * Check if something is a plausible authentication result header.
 * 
 * A header must be a single-line string that starts with
 * `Authentication-Results:`
 * 
 * @param {string} input
 * @returns {boolean}
 */
 function isValidAuthResultHeader(input){
    // make sure we have a plausible header
    if(!isValidHeader(input)) return false;

    // make sure the string starts with the expected text
    if(!input.startsWith('Authentication-Results:')) return false;

    // if we got here all is well, so return true
    return true;
}

/**
 * Check if something is a plausible spam report header.
 * 
 * A header must be a single-line string that starts with
 * `X-Forefront-Antispam-Report:`
 * 
 * @param {string} input
 * @returns {boolean}
 */
 function isValidForefrontSpamReportHeader(input){
    // make sure we have a plausible header
    if(!isValidHeader(input)) return false;

    // make sure the string starts with the expected text
    if(!input.startsWith('X-Forefront-Antispam-Report:')) return false;

    // if we got here all is well, so return true
    return true;
}

/**
 * Check if something is a plausible anti-spam header.
 * 
 * A header must be a single-line string that starts with
 * `X-Microsoft-Antispam:`
 * 
 * @param {string} input
 * @returns {boolean}
 */
function isValidMicrosoftAntiSpamHeader(input){
    // make sure we have a plausible header
    if(!isValidHeader(input)) return false;

    // make sure the string starts with the expected text
    if(!input.startsWith('X-Microsoft-Antispam:')) return false;

    // if we got here all is well, so return true
    return true;
}

/**
 * Parse a sanitised Office365 Forefront Span Report Header.
 * 
 * @see sanitiseMailHeader
 * @param {string} input 
 * @returns {object} Returns a plain object of the form:
 * ```
 * {
 *   senderIP: '1.1.1.1', // the IP address of the sender (CIP)
 *   spamScore: 0, // the numeric spam score (SCL)
 * }
 * ```
 * @throws {TypeError} A Type Error is thrown if a string is not passed.
 * @throws {RangeError} A Range Error is thrown if an invalid string is passed.
 */
function parseForefrontSpamReportHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');
    if(!isValidForefrontSpamReportHeader(input)) throw new RangeError('must pass a sanitised header');

    // strip off the header name
    let headerVal = input.replace(/^X-Forefront-Antispam-Report:[ ]/, '');

    // break the header down into its parts
    const header = {};
    let headerFields = headerVal.split(';');
    for(const field of headerFields){
        if(field === '') continue;
        const fieldMatch = field.match(/^(\w+):(.*)$/)
        if(fieldMatch){
            header[fieldMatch[1]] = fieldMatch[2];
        }else{
            console.debug('failed to parse field', field);
        }
    }
    console.log(header);

    // assemble the return value
    const ans = {
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
        flaggedDueToUserComplaints: header.SRV == 'BULK' ? true : false
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