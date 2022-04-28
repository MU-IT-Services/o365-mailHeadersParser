// data

/**
 * All the headers considered to be related to mail addressing.
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
 * All the headers considered to be related to mail routing.
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
 * All the headers considered to be related to security/spam filtering.
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
    const $securityAnalysisUL = $('#securityAnalysis-ul');
    const $customHeadersUL = $('#customHeaders-ul');
    const $securityReportDiv = $('#securityReport-div');
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
        let customHeaderNames = []; // an array of all the header names matching the specified custom prefix (if any)
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

        // also store the headers in lower case, and in lower-case with the dashes replaced with underscores
        // while looping over all the headers, also save any matching custom headers
        const customPrefix = $customHeadersPrefixTB.val().trim();
        for(const headerName of Object.keys(headers)){
            // store in lower case and with underscores
            const lcHeaderName = headerName.toLowerCase();
            const lcUunderScoreHeaderName = lcHeaderName.replaceAll('-', '_');
            if(lcHeaderName !== headerName){
                headers[lcHeaderName] = headers[headerName];
            }
            if(lcUunderScoreHeaderName !== headerName && lcUunderScoreHeaderName !== lcHeaderName){
                headers[lcUunderScoreHeaderName] = headers[headerName];
            }

            // check if custom header
            if(lcHeaderName.startsWith(customPrefix.toLowerCase())){
                customHeaderNames.push(headerName);
            }
        }
        customHeaderNames = customHeaderNames.sort();
        console.debug(headerList, headers, customHeaderNames);

        // genereate the security report
        const securityDetails = {
            ...parseAuthResultHeader(headers.authentication_results.value),
            ...parseOriginalAuthResultHeader(headers.authentication_results_original.value),
            ...parseForefrontSpamReportHeader(headers.x_forefront_antispam_report.value),
            ...parseMicrosoftAntiSpamHeader(headers.x_microsoft_antispam.value)
        };
        console.debug(securityDetails);

        // render all the headers
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
                }else if(customPrefix.length > 0 && header.name.toLowerCase().startsWith(customPrefix.toLowerCase())){
                    $header.addClass('bg-success bg-opacity-10');
                }
                $allHeadersUL.append($header);    
            }
        }else{
            $allHeadersUL.append($('<li>').addClass('list-group-item list-group-item-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> No Headers Found!'));
        }

        // render the full security report
        $securityReportDiv.empty();
        if(Object.keys(securityDetails).length > 0){
            const $securityReport = $('<pre>').addClass('json-container').append(prettyPrintJson.toHtml(securityDetails, {}));
            $securityReportDiv.append($securityReport);
        }else{
            $securityReportDiv.append($('<div>').addClass('alert alert-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> No Secrity/Spam Headers Found!'));
        }

        //
        // render the basics
        //
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
        if (headers['reply-to']) $basicsUL.append(generateBasicsLI('Reply To', headers['reply-to'].value));
        if (headers['return-path']) $basicsUL.append(generateBasicsLI('Return Path', headers['return-path'].value));
        $basicsUL.append(generateBasicsLI('To', headers.to? headers.to.value : 'UNKNOWN').addClass('fw-bold'));
        if (headers['delivered-to']) $basicsUL.append(generateBasicsLI('Also Delivered To', headers['delivered-to'].value));
        $basicsUL.append(generateBasicsLI('Message ID', headers['message-id']? headers['message-id'].value : 'UNKNOWN').addClass('fw-bold'));
        $basicsUL.append(generateBasicsLI('MS Network Message ID', headers['x-ms-exchange-organization-network-message-id']? headers['x-ms-exchange-organization-network-message-id'].value : 'UNKNOWN'));

        //
        // render the security summary
        //
        $securityAnalysisUL.empty();

        // a local function to render an info tooltip within the security analysis
        const appendInfo = ($li, info)=>{
            const $info = $('<i class="bi bi-info-circle-fill"></i>').attr('title', info);
            new bootstrap.Tooltip($info[0]);
            $li.append(' ').append($info);
        };

        // start with the authentication results header
        if(securityDetails.authenticationResultsHeaderSpecified){
            // start with compound auth
            const $compAuthLI = $('<li>').addClass('list-group-item').html('<strong>Compound Authentication:</strong> ');
            const appendCompauthReason = ($li)=>{
                if(securityDetails.compoundAuthentication.reasonCode !== '000'){
                    $info = $('<span>').addClass('text-muted').html(' <code class="code"></code> <span class="meaning"></span>');
                    $('.code', $info).text(securityDetails.compoundAuthentication.reasonCode);
                    $('.meaning', $info).text(securityDetails.compoundAuthentication.reasonMeaning);
                    $li.append($info);
                }
            };
            switch(securityDetails.compoundAuthentication.result){
                case 'pass':
                case 'softpass':
                    $compAuthLI.append($('<span>').addClass('badge bg-success').text(securityDetails.compoundAuthentication.result));
                    appendCompauthReason($compAuthLI);
                    break;
                case 'none':
                    $compAuthLI.append($('<span>').addClass('badge bg-warning').text('NOT PERFORMED'));
                    appendCompauthReason($compAuthLI);
                    break;
                case 'fail':
                    $compAuthLI.append($('<span>').addClass('badge bg-danger').text('FAIL'));
                    appendCompauthReason($compAuthLI);
                    break;
                case 'unknown':
                    $compAuthLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No Compound Auhentication details found in <code>Authentication-Results</code> header'));
                    break;
                default:
                    $compAuthLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.compoundAuthentication.result}</code>`));
            }
            $securityAnalysisUL.append($compAuthLI);

            // local function for adding details to SFP, DKIM, or DMARC
            const appendDetails = ($li, result)=>{
                $li.append(' ').append($('<span>').addClass('text-muted font-monospace').text(result.details));
            };

            // add SPF
            const $spfLI = $('<li>').addClass('list-group-item').html('<strong>SPF Validation:</strong> ');
            switch(securityDetails.spf.result){
                case 'none':
                    $spfLI.append($('<span>').addClass('badge bg-secondary').text('no SPF record'));
                    appendDetails($spfLI, securityDetails.spf);
                    break;
                case 'pass':
                    $spfLI.append($('<span>').addClass('badge bg-success').text('pass'));
                    appendDetails($spfLI, securityDetails.spf);
                    break;
                case 'neutral':
                    $spfLI.append($('<span>').addClass('badge bg-primary').text('neutral'));
                    appendDetails($spfLI, securityDetails.spf);
                    break;
                case 'fail':
                    $spfLI.append($('<span>').addClass('badge bg-danger').text(securityDetails.spf.result));
                    appendDetails($spfLI, securityDetails.spf);
                    break;
                case 'softfail':
                    $spfLI.append($('<span>').addClass('badge bg-danger').text('soft fail'));
                    appendInfo($spfLI, 'sender denied but SPF record is permissive (~all), not enforcing (-all)');
                    appendDetails($spfLI, securityDetails.spf);
                    break;
                case 'temperror':
                    $spfLI.append($('<span>').addClass('badge bg-warning').text('temporary error'));
                    appendInfo($spfLI, 'SPF processing failed because of a temporary problem, usually a DNS lookup failure');
                    appendDetails($spfLI, securityDetails.spf);
                    break;
                case 'permerror':
                    $spfLI.append($('<span>').addClass('badge bg-danger').text('permanent error'));
                    appendInfo($spfLI, 'SPF processing failed because of a problem with the record, usally a syntax error in the record itself');
                    appendDetails($spfLI, securityDetails.spf);
                    break;
                case 'unknown':
                    $spfLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No SPF details found in <code>Authentication-Results</code> header'));
                    break;
                default:
                    $spfLI.append($('<strong>').addClass('text-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.spf.result}</code>'));
            }
            $securityAnalysisUL.append($spfLI);

            // add DKIM
            const $dkimLI = $('<li>').addClass('list-group-item').html('<strong>DKIM Validation:</strong> ');
            switch(securityDetails.dkim.result){
                case 'none':
                    $dkimLI.append($('<span>').addClass('badge bg-secondary').text('message not signed'));
                    break;
                case 'pass':
                    $dkimLI.append($('<span>').addClass('badge bg-success').text('pass'));
                    appendDetails($dkimLI, securityDetails.dkim);
                    break;
                case 'fail':
                    $dkimLI.append($('<span>').addClass('badge bg-danger').text(securityDetails.dkim.result));
                    appendDetails($dkimLI, securityDetails.dkim);
                    break;
                case 'unknown':
                    $dkimLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No DKIM details found in <code>Authentication-Results</code> header'));
                    break;
                default:
                    $dkimLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.dkim.result}</code>`));
            }
            $securityAnalysisUL.append($dkimLI);

            // add DMARC
            const $dmarcLI = $('<li>').addClass('list-group-item').html('<strong>DMARC Validation:</strong> ');
            switch(securityDetails.dmarc.result){
                case 'none':
                    $dmarcLI.append($('<span>').addClass('badge bg-secondary').text('no DMARC record'));
                    break;
                case 'pass':
                    $dmarcLI.append($('<span>').addClass('badge bg-success').text('pass'));
                    appendDetails($dmarcLI, securityDetails.dmarc);
                    break;
                case 'bestguesspass':
                    $dmarcLI.append($('<span>').addClass('badge bg-success').text('inferred pass'));
                    appendInfo($dmarcLI, 'There is no DMARC record for the domain, but if a typical record existed, it would have passed');
                    appendDetails($dmarcLI, securityDetails.dmarc);
                    break;
                case 'fail':
                    $dmarcLI.append($('<span>').addClass('badge bg-danger').text(securityDetails.dmarc.result));
                    appendDetails($dmarcLI, securityDetails.dmarc);
                    break;
                case 'temperror':
                    $dmarcLI.append($('<span>').addClass('badge bg-warning').text('temporary error'));
                    appendInfo($dmarcLI, 'DMARC processing failed because of a temporary problem, usually a DNS lookup failure');
                    appendDetails($dmarcLI, securityDetails.dmarc);
                    break;
                case 'permerror':
                    $dmarcLI.append($('<span>').addClass('badge bg-danger').text('permanent error'));
                    appendInfo($dmarcLI, "DMARC processing failed because of a problem retrieving or processing the DNS record. This usually happens when there is a syntax error in the record, or, when the domain name doesn't reslove on the public internet (e.g. cron on a host without a public DNS name).");
                    appendDetails($dmarcLI, securityDetails.dmarc);
                    break;
                case 'unknown':
                    $dmarcLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No DKIM details found in <code>Authentication-Results</code> header'));
                    break;
                default:
                    $dmarcLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${securityDetails.dmarc.result}</code>`));
            }
            $securityAnalysisUL.append($dmarcLI);
        }else{
            $securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>Authentication-Results</code> header found'));
        }

        // next the spam report header
        if(securityDetails.spamReportHeaderSpecified){
            // start with the spam score
            const $spamScoreLI = $('<li>').addClass('list-group-item').html('<strong>Spam Filter:</strong> ');
            const $scl = $('<span>').addClass('badge').html('SCL <span class="code font-monospace"></span> — <span class="meaning"></span>');
            const sclDesc = sclMeaning(securityDetails.spamScore);
            $('.code', $scl).text(securityDetails.spamScore);
            $('.meaning', $scl).text(sclDesc);
            switch(sclDesc){
                case 'not spam':
                    $scl.addClass('bg-success');
                    break;
                case 'spam':
                case 'high confidence spam':
                    $scl.addClass('bg-danger');
                    break;
                 default:
                    $scl.addClass('bg-secondary');
            }
            $spamScoreLI.append($scl);
            if(securityDetails.spamFilterAction !== 'none'){
                $spamScoreLI.append(' ').append($('<span>').text(securityDetails.spamFilterAction));
            }
            $securityAnalysisUL.append($spamScoreLI);
            
            // finish with the quarantine info
            const $quarantineLI = $('<li>').addClass('list-group-item').html('<strong>Quarantine Details:</strong> ');
            const $quarantinedBadge = $('<span>').addClass('badge');
            if(securityDetails.releasedFromQuarantine){
                // the mail was relesed from quarantine
                $quarantinedBadge.text('Released from Quarantine').addClass('bg-warning');
            }else{
                // the mail was not quarantined
                $quarantinedBadge.text('Not Quarantined').addClass('bg-success');
            }
            $quarantineLI.append($quarantinedBadge);
            if(securityDetails.releasedFromQuarantine){
                if(securityDetails.OriginalAuthenticationResultsHeaderSpecified){
                    const $originalAuthResult = $('<span>').text(securityDetails.originalAuthResult).addClass('badge');
                    switch(securityDetails.originalAuthResult){
                        case 'fail':
                            $originalAuthResult.addClass('bg-error');
                            break;
                        case 'pass':
                            $originalAuthResult.addClass('bg-success');
                            break;
                        default:
                            $originalAuthResult.addClass('bg-danger');
                    }
                    $quarantineLI.append($('<p>').text('Pre-quarantine Authentication Result: ').addClass('text-muted m-0').append($originalAuthResult));
                }else{
                    $quarantineLI.append($('<p>').text('No pre-quarantine authentication header found').addClass('text-muted fst-italic m-0'));
                }
            }
            $securityAnalysisUL.append($quarantineLI);
        }else{
            $securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>X-Forefront-Antispam-Report</code> header found'));
        }

        // next the bulk mail header
        if(securityDetails.bulkMailReportHeaderSpecified){
            const $bulkMailScoreLI = $('<li>').addClass('list-group-item').html('<strong>Bulk Mail Filter:</strong> ');
            const $bcl = $('<span>').html('<span class="badge">BCL <span class="code font-monospace"></span></span> <span class="meaning text-muted"></span>');
            const bclDesc = bclMeaning(securityDetails.bulkMailScore);
            $('.code', $bcl).text(securityDetails.bulkMailScore);
            $('.meaning', $bcl).text(bclDesc);
            if(bclDesc === 'not from bulk mail sender' || bclDesc.includes('few user complaints')){
                $('.badge', $bcl).addClass('bg-success');
            }else if(bclDesc.includes('some user complaints')){
                $$('.badge', $bcl).addClass('bg-warning');
            }else if(bclDesc.includes('many user complaints')){
                $('.badge', $bcl).addClass('bg-danger');
            }else{
                $('.badge', $bcl).addClass('bg-secondary');
            }
            $bulkMailScoreLI.append($bcl);
            $securityAnalysisUL.append($bulkMailScoreLI);
        }else{
            $securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>X-Microsoft-Antispam</code> header found'));
        }

        // end with the details to submit the mail to Microsoft for review
        if(headers['x-ms-exchange-organization-network-message-id']){
            const $submitToMSLI = $('<li>').addClass('list-group-item list-group-item-info')
            $submitToMSLI.html(`<i class="bi bi-info-circle"></i> If this mail was mishandled by Micorosft's filters you can submit it for review using the Network Message ID <code>${headers['x-ms-exchange-organization-network-message-id'].value}</code>. <a href="https://security.microsoft.com/reportsubmission?viewid=admin" rel="nofollow" target="_blank" class="btn btn-outline-primary btn-sm">Submit to MS <i class="bi bi-box-arrow-up-right"></i></a>`);
            $securityAnalysisUL.append($submitToMSLI);
        }

        //
        // render the custom headers
        //
        $customHeadersUL.empty();
        if(customPrefix.length > 0){
            if(customHeaderNames.length > 0){
                for(const headerName of customHeaderNames){
                    const $header = $('<li class="list-group-item"><code class="header-name"></code><br><span class="font-monospace header-value"></span></li>');
                    $('.header-name', $header).text(headers[headerName].name);
                    $('.header-value', $header).text(headers[headerName].value);
                    $customHeadersUL.append($header);
                }
            }else{
                $customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-warning').html(`<i class="bi bi-exclamation-triangle-fill"></i> found no headers pre-fixed with <code>${customPrefix}</code>`));
            }
        }else{
            $customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-info').html('<strong><i class="bi bi-info-circle-fill"></i> No custom prefix specified</strong> — enter a prefix in the form to spotlight matching headers'));
        }
    });

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