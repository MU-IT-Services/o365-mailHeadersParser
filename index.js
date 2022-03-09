// data

/**
 * All the headers considered to be related to mail addressing in the order they
 * should be displayed.
 * 
 * @type {string[]}
 */
const ADDRESSING_HEADERS = [
    'To',
    'From',
    'Reply-To',
    'Return-Path'
];

/**
 * A lookup of the headers to be marked as addressing-related.
 * 
 * @type {object.<string, boolean>}
 */
const ADDRESSING_HEADERS_LOOKUP = {};
for(const header of ADDRESSING_HEADERS){
    ADDRESSING_HEADERS_LOOKUP[header] = true;
    ADDRESSING_HEADERS_LOOKUP[header.toLowerCase()] = true;
}

/**
 * All the headers considered to be related to mail routing in the order they
 * should be displayed.
 * 
 * @type {string[]}
 */
 const ROUTING_HEADERS = [
    'Received'
];

/**
 * A lookup of the headers to be marked as routing-related.
 * 
 * @type {object.<string, boolean>}
 */
const ROUTING_HEADERS_LOOKUP = {};
for(const header of ROUTING_HEADERS) {
    ROUTING_HEADERS_LOOKUP[header] = true;
    ROUTING_HEADERS_LOOKUP[header.toLowerCase()] = true;
}

/**
 * All the headers considered to be related to mail seurity in the order they
 * should be displayed.
 * 
 * @type {string[]}
 */
 const SECURITY_HEADERS = [
    'Authentication-Results',
    'X-Forefront-Antispam-Report',
    'X-Microsoft-Antispam'
];

/**
 * A lookup of the headers to be marked as security headers.
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
}

// Document ready handler
$.when( $.ready ).then(function() {
    const $fullHeadersTA = $('#fullHeaders-ta');
    const $customHeadersPrefixTB = $('#customHeadersPrefix-tb');
    const $processBtn = $('#process_btn');
    const $basicsUL = $('#basics-ul');
    const $allHeadersUL = $('#allHeaders-ul');

    // local functions to validate the two forms
    const validateHeadersFn = ()=>{ validateHeadersForm($fullHeadersTA, $customHeadersPrefixTB) };

    // add form validation
    $fullHeadersTA.on('input', validateHeadersFn);
    $customHeadersPrefixTB.on('input', validateHeadersFn);
    validateHeadersFn();

    // add an event handler to the process button
    $processBtn.click(()=>{
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
        const headerList = []; // an in-order list of headers, were each header is an object indexed by name, and value
        const headers = {}; // a lookup of header values indexed by name
        const wipHeader = { name: '', value: '', index: 0 };
        const storeWIPHeader = ()=>{
            if(wipHeader.name.length > 0){
                // store the finished header

                // always push a shallow clone into the sequential list
                headerList.push({...wipHeader});

                // insert into the headers dictionary as a single or mutli-value header as appropriate
                const newHeader = {...wipHeader}; // a shallow clone
                if(headers[newHeader.name]){
                    if(headers[newHeader.name].multiValue){
                        // already a multi-value, just append
                        headers[newHeader.name].values.push(newHeader);
                    }else{
                        // currently a single-value header, convert to multi-value one
                        const singleHeaderDetails = { ...headers[newHeader.name] }; // shallow clone
                        headers[newHeader.name].multiValue = true;
                        headers[newHeader.name].values = [singleHeaderDetails,  newHeader];
                        delete headers[newHeader.name].value;
                        delete headers[newHeader.name].index;
                    }
                }else{
                    // never-before seen header, so just save
                    headers[newHeader.name] = newHeader;
                }

                // start a new WIP header
                wipHeader.name = '';
                wipHeader.value = '';
                wipHeader.index++;
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
                    wipHeader.name = headerMatch[1];
                    wipHeader.value = headerMatch[2] || '';
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
        // store any as-yet unsaved WIP header
        storeWIPHeader();

        // also store the headers in lower case
        for(const headerName of Object.keys(headers)){
            const lcHeaderName = headerName.toLowerCase();
            if(lcHeaderName !== headerName){
                headers[lcHeaderName] = headers[headerName];
            }
        }
        console.debug(headerList, headers);

    //     // populate the relevant text areas and validate the form
    //     $authResultsHeaderTA.val(headers['Authentication-Results'] ? 'Authentication-Results: ' + headers['Authentication-Results'] : '');
    //     $forefrontSpamReportTA.val(headers['X-Forefront-Antispam-Report'] ? 'X-Forefront-Antispam-Report: ' + headers['X-Forefront-Antispam-Report'] : '');
    //     $microsoftAntiSpamHeaderTA.val(headers['X-Microsoft-Antispam'] ? 'X-Microsoft-Antispam: ' + headers['X-Microsoft-Antispam'] : '');
    //     if(validateHeadersFn()) $parseBtn.focus();

    //     // blank the additional headers alert and collect the appropriate headers
    //     const additionalHeaders = {};
    //     $additionalHeadersDiv.empty();

    //     // if required, find the routing headers
    //     if($extractRoutingHeadersCB.prop('checked')){
    //         for(const header of ROUTING_HEADERS){
    //             if(headers[header]) additionalHeaders[header] = headers[header];
    //         }
    //     }else{
    //         $additionalHeadersDiv.append($('<p>').text('Extraction of routing headers disabled.').addClass('text-muted'));
    //     }

    //     // if there's a custom header prefix, match any headers and update the alert
    //     let customPrefix = $customHeadersPrefixTB.val();
    //     if(customPrefix.length > 0){
    //         for(const header of Object.keys(headers).sort()){
    //             if(header.startsWith(customPrefix)){
    //                 additionalHeaders[header] = headers[header];
    //             }
    //         }
    //     }else{
    //         $additionalHeadersDiv.append($('<p>').text('No matching custom headers found').addClass('text-muted'));
    //     }

    //     // add the additional headers
    //     $additionalHeadersDiv.append($('<pre>').addClass('json-container').append(prettyPrintJson.toHtml(additionalHeaders, {})));

        // render the basics
        $basicsUL.empty();
        const generateBasicsLI = (n, v)=>{
            const $header = $('<li class="list-group-item"><code class="header-name"></code>: <span class="font-monospace header-value"></span></li>');
            $('.header-name', $header).text(n);
            $('.header-value', $header).text(v);
            return $header;
        };
        $basicsUL.append(generateBasicsLI('Subject', headers.subject ? headers.subject.value : '').addClass('fw-bold'));
        $basicsUL.append(generateBasicsLI('Date', headers.date? headers.date.value : 'UNKNOWN'));
        $basicsUL.append(generateBasicsLI('From', headers.from ? headers.from.value : 'UNKNOWN').addClass('fw-bold'));
        if (headers['return-path']) $basicsUL.append(generateBasicsLI('Return Path', headers['return-path'].value));
        if (headers['reply-to']) $basicsUL.append(generateBasicsLI('Reply To', headers['reply-to'].value));

        // render all the headers
        const customPrefix = $customHeadersPrefixTB.val().trim();
        $allHeadersUL.empty();
        if(headerList. length > 0){
            for(const header of headerList){
                const $header = $('<li class="list-group-item"><code class="header-name"></code><br><span class="font-monospace header-value"></span></li>');
                $('.header-name', $header).text(header.name);
                $('.header-value', $header).text(header.value);
                if(SECURITY_HEADERS_LOOKUP[header.name.toLowerCase()]){
                    $header.addClass('bg-danger bg-opacity-10');
                }else if(ROUTING_HEADERS_LOOKUP[header.name.toLowerCase()]){
                    $header.addClass('bg-warning bg-opacity-10');
                }else if(ADDRESSING_HEADERS_LOOKUP[header.name.toLowerCase()]){
                    $header.addClass('bg-primary bg-opacity-10');
                }else if(customPrefix.length > 0 && header.name.startsWith(customPrefix)){
                    $header.addClass('bg-success bg-opacity-10');
                }
                $allHeadersUL.append($header);    
            }
        }else{
            $allHeadersUL.append($('<li>').addClass('list-group-item list-group-item-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> No Headers Found!'));
        }
    });

  

    // // add an event handler to the parse button
    // $parseBtn.click(()=>{
    //     const messageDetails = {
    //         ...parseAuthResultHeader(sanitiseMailHeader($authResultsHeaderTA.val())),
    //         ...parseForefrontSpamReportHeader(sanitiseMailHeader($forefrontSpamReportTA.val())),
    //         ...parseMicrosoftAntiSpamHeader(sanitiseMailHeader($microsoftAntiSpamHeaderTA.val()))
    //     };
    //     const $out = $('<pre>').addClass('json-container').append(prettyPrintJson.toHtml(messageDetails, {}));
    //     $('#output_div').empty().append($out);
    // });

    // focus the full headers field
    $fullHeadersTA.focus();
});

/**
 * Validate the header details form.
 * 
 * @param {jQuery} $fullHeadersTA - a jQuery object representing the
 * full headers text area.
 * @param {jQuery} $customHeadersPrefixTB - a jQuery object representing the
 * optional custom header prefix.
 * @return {boolean}
 */
 function validateHeadersForm($fullHeadersTA, $customHeadersPrefixTB){
    // make sure we were passed two jQuery objects
    for(const $textInput of [$fullHeadersTA, $customHeadersPrefixTB]){
        if(!$textInput instanceof $){
            console.warn('extraction form validation must be passed two jQuery objects');
            return false;
        }
    }

    // validate each input
    let numError = 0;
    let numMissingRequired = 0;
    if($fullHeadersTA.val().match(/\w/)){
        $fullHeadersTA.removeClass('is-invalid').addClass('is-valid');
    }else{
        numMissingRequired++;
        $fullHeadersTA.removeClass('is-valid');
        if($fullHeadersTA.val() !== ''){
            $fullHeadersTA.addClass('is-invalid');
            numError++;
        }
    }
    if($customHeadersPrefixTB.val().length > 0){
        $customHeadersPrefixTB.addClass('is-valid');
    }else{
        $customHeadersPrefixTB.removeClass('is-valid');
    }
    
    // if we've no errors and no missing required fields, enable the button
    if(numError === 0 && numMissingRequired === 0){
        $fullHeadersTA.closest('form').find('button').prop('disabled', false);
        return true;
    }

    // default to disabling and return false
    $fullHeadersTA.closest('form').find('button').prop('disabled', true);
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
 * Parse an authentication results header.
 * 
 * @param {string} input 
 * @return {object} Returns an object of the form:
 * ```
 * {
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
    if(input === '') return {};
    if(!isValidAuthResultHeader(input)) throw new RangeError('must pass a sanitised header');

    // initiaise the return value
    const ans = {
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

    // strip off the header name
    let headerVal = input.replace(/^Authentication-Results:[ ]/, '');

    // split the value on semi-colon to get the various parts
    const headerParts = headerVal.trim().split(/;[ ]?/);

    // process each part
    for(const headerPart of headerParts){
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
                    ans.dmarc.details = headerPart;
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
 * Parse a sanitised Office365 Forefront Span Report Header.
 * 
 * @see sanitiseMailHeader
 * @param {string} input 
 * @returns {object} Returns a plain object of the form:
 * ```
 * {
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
 *   flaggedDueToUserComplaints: false
 * }
 * ```
 * @throws {TypeError} A Type Error is thrown if a string is not passed.
 * @throws {RangeError} A Range Error is thrown if an invalid string is passed.
 */
function parseForefrontSpamReportHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');
    if(input === '') return {};
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

/**
 * Parse a Microsoft Anti-Spam header.
 * 
 * @param {string} input 
 * @return {object} Returns an object of the form:
 * ```
 * {
 *   bulkMailScore: 1
 * }
 * ```
 * @throws {TypeError} A Type Error is thrown if a string is not passed.
 * @throws {RangeError} A Range Error is thrown if an invalid string is passed.
 */
function parseMicrosoftAntiSpamHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');
    if(input === '') return {};
    if(!isValidMicrosoftAntiSpamHeader(input)) throw new RangeError('must pass a sanitised header');

    // extract the BCL and return
    const bclMatch = input.match(/BCL:(\d+)/);
    return {
        bulkMailScore: bclMatch ? parseInt(bclMatch[1]) : -1
    };
}