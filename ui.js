// ----------------------------------------------------------------------------
// UI Helper Functions 
// ----------------------------------------------------------------------------
// Functions for rendering the UI, these functions should be called by event
// handlers within theUI.

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
 * @property {jQuery} form.parseDirectionRG — The radio group representing the
 *   direction (inbound/outbound) the headers should be parsed for.
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
        parseDirectionRG: $(),
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
// === UI Component Generators ================================================
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
 * Generate a basic header list item. Both the header title and value are
 * rendered in a monospaced font.
 * 
 * @param {HeaderObject} header
 * @returns {jQuyery}
 */
function generateHeaderLI(header){
    const $ans = $('<li class="list-group-item"><code class="header-name"></code><br><span class="font-monospace header-value"></span></li>');
    $('.header-name', $ans).text(header.name);
    $('.header-value', $ans).text(header.value);
    return $ans;
}

/**
 * Generate a header list item for a canonical header.
 * 
 * @param {CanonicalHeaderObject} canonicalHeader
 * @returns {jQuyery}
 */
function generateCanonicalHeaderLI(canonicalHeader){
    // start with just a header name placeholder with the name injected
    const $ans = $('<li class="list-group-item"><code class="header-name"></code>: </li>');
    $('.header-name', $ans).text(canonicalHeader.name);

    // add a single value if appropriate
    if(canonicalHeader.value || canonicalHeader.isMissing){
        $ans.append($('<span>').addClass('font-monospace header-value'));
        $('.header-value', $ans).text(canonicalHeader.isMissing ? 'UNKNOWN' : canonicalHeader.value);
    }

    // add multi-values if needed
    const doShowMultiVals = canonicalHeader.values && canonicalHeader.values.length ? true : false;
    if(doShowMultiVals){
        const $multiValUL = $('<ul>').addClass('list-unstyled');
        for(const val of canonicalHeader.values){
            const $multiValLI = $('<li>');
            $multiValLI.append($('<span>').addClass('font-monospace').text(val));
            $multiValUL.append($multiValLI);
        }
        $ans.append($multiValUL);
    }

    // add error if needed
    if(canonicalHeader.error){
        $ans.addClass('list-group-item-warning');
        if(!doShowMultiVals) $ans.append('<br>');
        $ans.append($('<small>').addClass('fw-normal').text(canonicalHeader.error).prepend('<i class="bi bi-exclamation-triangle-fill"></i> '));
    }

    // return the LI
    return $ans;
}

//
// === Form Validation Functions ==============================================
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
// === UI Rendering Fuctions ==================================================
//

//
// -- Notification Functions --------------------------------------------------
//

/**
 * Output a parse warning alert.
 * 
 * @param {string} warningText
 */
 function showParseWarning(warningText){
    $alert = $('<div>').addClass('alert alert-warning').text(warningText);
    $alert.prepend('<i class="bi bi-exclamation-triangle-fill"></i> ');
    $UI.output.alerts.append($alert);
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
// -- Component Renderers -----------------------------------------------------
//

/**
 * Render the full list of headers.
 */
 function renderAllHeaders(){
    // empty the header UL
    $UI.output.allHeadersUL.empty();

    // loop over all the loaded headers and append them to the UL
    for(const header of DATA.listAsReceived){
        const $header = generateHeaderLI(header);
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
 * Render the full security report JSON.
 */
function renderSecurityReport(){
    $UI.output.securityReportDiv.empty();
    if(Object.keys(DATA.securityReport).length > 0){
             const $securityReport = $('<pre>').addClass('json-container').append(prettyPrintJson.toHtml(DATA.securityReport, {}));
             $UI.output.securityReportDiv.append($securityReport);
    }else{
        $UI.output.securityReportDiv.append($('<div>').addClass('alert alert-info').html('<i class="bi bi-info-circle-fill"></i> No secrity/spam headers found'));
    }
}

/**
 * Render the *Basics* card.
 */
function renderBasicsCard(){
    // empty the UL containing the data
    $UI.output.basicsUL.empty();

    $UI.output.basicsUL.append(generateCanonicalHeaderLI(DATA.canonicalByID.subject).addClass('fw-bold'));
    $UI.output.basicsUL.append(generateCanonicalHeaderLI(DATA.canonicalByID.date));
    const $fromLI = generateCanonicalHeaderLI(DATA.canonicalByID.from).addClass('fw-bold');
    $UI.output.basicsUL.append($fromLI);
    if(DATA.canonicalByID.reply_to.value){
        if(DATA.canonicalByID.reply_to.error){
            $UI.output.basicsUL.append(generateCanonicalHeaderLI(DATA.canonicalByID.reply_to));
        }else{
            if(DATA.canonicalByID.reply_to.value == DATA.canonicalByID.from.value){
                $fromLI.append(' ').append($('<small>').html('<i class="bi bi-plus-circle"></i> Reply To').addClass('badge bg-secondary fw-normal'));
            }else{
                const $replyTo = $('<small class="text-nowrap text-muted fw-normal"><code>Reply-To</code>: <span class="font-monospace reply-to-header-value"></span></small>');
                $('.reply-to-header-value', $replyTo).text(DATA.canonicalByID.reply_to.value);
                $fromLI.append(' ').append($replyTo);
            }
        }
    }
    if(DATA.canonicalByID.return_path.error){
        $UI.output.basicsUL.append(generateCanonicalHeaderLI(DATA.canonicalByID.return_path));
    }else{
        if(DATA.canonicalByID.return_path.value){
            const $returnPath = $('<small class="text-nowrap text-muted fw-normal"><code>Return-Path</code>: <span class="font-monospace return-path-header-value"></span></small>');
            $('.return-path-header-value', $returnPath).text(DATA.canonicalByID.return_path.value);
            $fromLI.append(' ').append($returnPath);
        }
    }
    const $toLI = generateCanonicalHeaderLI(DATA.canonicalByID.to).addClass('fw-bold');
    $UI.output.basicsUL.append($toLI);
    if(DATA.canonicalByID.delivered_to.error){
        $UI.output.basicsUL.append(generateCanonicalHeaderLI(DATA.canonicalByID.delivered_to));
    }else{
        if(DATA.canonicalByID.delivered_to.value){
            const $deliveredTo = $('<small class="text-muted fw-normal">Also delivered to <span class="font-monospace delivered-to-header-value"></span></small>');
            $('.delivered-to-header-value', $deliveredTo).text(DATA.canonicalByID.delivered_to.value);
            $toLI.append(' ').append($deliveredTo);
        }
    }
    $UI.output.basicsUL.append(generateCanonicalHeaderLI(DATA.canonicalByID.message_id).addClass('fw-bold').addClass('fw-bold'));
}

/**
 * Render the *Security Report* card.
 */
function renderSecurityReportCard(){
    $UI.output.securityAnalysisUL.empty();

    // a local function to render an info tooltip within the security analysis
    const appendInfo = ($li, info)=>{
        const $info = $('<i class="bi bi-info-circle-fill"></i>').attr('title', info);
        new bootstrap.Tooltip($info[0]);
        $li.append(' ').append($info);
    };

    // start with the authentication results header
    if(DATA.securityReport.authenticationResultsHeaderSpecified){
        // start with compound auth
        const $compAuthLI = $('<li>').addClass('list-group-item').html('<strong>Compound Authentication:</strong> ');
        const appendCompauthReason = ($li)=>{
            if(DATA.securityReport.compoundAuthentication.reasonCode !== '000'){
                $info = $('<span>').addClass('text-muted').html(' <code class="code"></code> <span class="meaning"></span>');
                $('.code', $info).text(DATA.securityReport.compoundAuthentication.reasonCode);
                $('.meaning', $info).text(DATA.securityReport.compoundAuthentication.reasonMeaning);
                $li.append($info);
            }
        };
        switch(DATA.securityReport.compoundAuthentication.result){
            case 'pass':
            case 'softpass':
                $compAuthLI.append($('<span>').addClass('badge bg-success').text(DATA.securityReport.compoundAuthentication.result));
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
                $compAuthLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${DATA.securityReport.compoundAuthentication.result}</code>`));
        }
        $UI.output.securityAnalysisUL.append($compAuthLI);

        // local function for adding details to SFP, DKIM, or DMARC
        const appendDetails = ($li, result)=>{
            $li.append('<br>').append($('<small>').addClass('text-muted font-monospace').text(result.details));
        };

        // add SPF
        const $spfLI = $('<li>').addClass('list-group-item').html('<strong>SPF Validation:</strong> ');
        switch(DATA.securityReport.spf.result){
            case 'none':
                $spfLI.append($('<span>').addClass('badge bg-secondary').text('no SPF record'));
                appendDetails($spfLI, DATA.securityReport.spf);
                break;
            case 'pass':
                $spfLI.append($('<span>').addClass('badge bg-success').text('pass'));
                appendDetails($spfLI, DATA.securityReport.spf);
                break;
            case 'neutral':
                $spfLI.append($('<span>').addClass('badge bg-primary').text('neutral'));
                appendDetails($spfLI, DATA.securityReport.spf);
                break;
            case 'fail':
                $spfLI.append($('<span>').addClass('badge bg-danger').text(DATA.securityReport.spf.result));
                appendDetails($spfLI, DATA.securityReport.spf);
                break;
            case 'softfail':
                $spfLI.append($('<span>').addClass('badge bg-danger').text('soft fail'));
                appendInfo($spfLI, 'sender denied but SPF record is permissive (~all), not enforcing (-all)');
                appendDetails($spfLI, DATA.securityReport.spf);
                break;
            case 'temperror':
                $spfLI.append($('<span>').addClass('badge bg-warning').text('temporary error'));
                appendInfo($spfLI, 'SPF processing failed because of a temporary problem, usually a DNS lookup failure');
                appendDetails($spfLI, DATA.securityReport.spf);
                break;
            case 'permerror':
                $spfLI.append($('<span>').addClass('badge bg-danger').text('permanent error'));
                appendInfo($spfLI, 'SPF processing failed because of a problem with the record, usally a syntax error in the record itself');
                appendDetails($spfLI, DATA.securityReport.spf);
                break;
            case 'unknown':
                $spfLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No SPF details found in <code>Authentication-Results</code> header'));
                break;
            default:
            $spfLI.append($('<strong>').addClass('text-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${DATA.securityReport.spf.result}</code>'));
        }
        $UI.output.securityAnalysisUL.append($spfLI);

        // add DKIM
        const $dkimLI = $('<li>').addClass('list-group-item').html('<strong>DKIM Validation:</strong> ');
        switch(DATA.securityReport.dkim.result){
            case 'none':
                $dkimLI.append($('<span>').addClass('badge bg-secondary').text('message not signed'));
                break;
            case 'pass':
                $dkimLI.append($('<span>').addClass('badge bg-success').text('pass'));
                appendDetails($dkimLI, DATA.securityReport.dkim);
                break;
            case 'fail':
                $dkimLI.append($('<span>').addClass('badge bg-danger').text(DATA.securityReport.dkim.result));
                appendDetails($dkimLI, DATA.securityReport.dkim);
                break;
            case 'unknown':
                $dkimLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No DKIM details found in <code>Authentication-Results</code> header'));
                break;
            default:
                $dkimLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${DATA.securityReport.dkim.result}</code>`));
        }
        $UI.output.securityAnalysisUL.append($dkimLI);

        // add DMARC
        const $dmarcLI = $('<li>').addClass('list-group-item').html('<strong>DMARC Validation:</strong> ');
        switch(DATA.securityReport.dmarc.result){
            case 'none':
                $dmarcLI.append($('<span>').addClass('badge bg-secondary').text('no DMARC record'));
                break;
            case 'pass':
                $dmarcLI.append($('<span>').addClass('badge bg-success').text('pass'));
                appendDetails($dmarcLI, DATA.securityReport.dmarc);
                break;
            case 'bestguesspass':
                $dmarcLI.append($('<span>').addClass('badge bg-success').text('inferred pass'));
                appendInfo($dmarcLI, 'There is no DMARC record for the domain, but if a typical record existed, it would have passed');
                appendDetails($dmarcLI, DATA.securityReport.dmarc);
                reak;
            case 'fail':
                $dmarcLI.append($('<span>').addClass('badge bg-danger').text(DATA.securityReport.dmarc.result));
                appendDetails($dmarcLI, DATA.securityReport.dmarc);
                break;
            case 'temperror':
                $dmarcLI.append($('<span>').addClass('badge bg-warning').text('temporary error'));
                appendInfo($dmarcLI, 'DMARC processing failed because of a temporary problem, usually a DNS lookup failure');
                appendDetails($dmarcLI, DATA.securityReport.dmarc);
                break;
            case 'permerror':
                $dmarcLI.append($('<span>').addClass('badge bg-danger').text('permanent error'));
                appendInfo($dmarcLI, "DMARC processing failed because of a problem retrieving or processing the DNS record. This usually happens when there is a syntax error in the record, or, when the domain name doesn't reslove on the public internet (e.g. cron on a host without a public DNS name).");
                appendDetails($dmarcLI, DATA.securityReport.dmarc);
                break;
            case 'unknown':
                $dmarcLI.append($('<strong>').addClass('text-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> No DKIM details found in <code>Authentication-Results</code> header'));
                break;
            default:
            $dmarcLI.append($('<strong>').addClass('text-danger').html(`<i class="bi bi-exclamation-octagon-fill"></i> Failed to parse — unexpected result <code>${DATA.securityReport.dmarc.result}</code>`));
        }
        $UI.output.securityAnalysisUL.append($dmarcLI);
    }else{
        $UI.output.securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>Authentication-Results</code> header found'));
    }

    // next the spam report header
    if(DATA.securityReport.spamReportHeaderSpecified){
        // start with the spam score
        const $spamScoreLI = $('<li>').addClass('list-group-item').html('<strong>Spam Filter:</strong> ');
        const $scl = $('<span>').addClass('badge').html('SCL <span class="code font-monospace"></span> — <span class="meaning"></span>');
        const sclDesc = sclMeaning(DATA.securityReport.spamScore);
        $('.code', $scl).text(DATA.securityReport.spamScore);
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
        if(DATA.securityReport.spamFilterAction !== 'none'){
            $spamScoreLI.append(' ').append($('<span>').text(DATA.securityReport.spamFilterAction));
        }
        $UI.output.securityAnalysisUL.append($spamScoreLI);
            
        // finish with the quarantine info
        const $quarantineLI = $('<li>').addClass('list-group-item').html('<strong>Quarantine Details:</strong> ');
        const $quarantinedBadge = $('<span>').addClass('badge');
        if(DATA.securityReport.releasedFromQuarantine){
            // the mail was relesed from quarantine
            $quarantinedBadge.text('Released from Quarantine').addClass('bg-warning');
        }else{
            // the mail was not quarantined
            $quarantinedBadge.text('Not Quarantined').addClass('bg-success');
        }
        $quarantineLI.append($quarantinedBadge);
        if(DATA.securityReport.releasedFromQuarantine){
            if(DATA.securityReport.OriginalAuthenticationResultsHeaderSpecified){
                const $originalAuthResult = $('<span>').text(DATA.securityReport.originalAuthResult).addClass('badge');
                switch(DATA.securityReport.originalAuthResult){
                    case 'fail':
                        $originalAuthResult.addClass('bg-error');
                        break;
                    case 'pass':
                        $originalAuthResult.addClass('bg-success');
                        break;
                    default:
                        $originalAuthResult.addClass('bg-danger');
                }
                $quarantineLI.append('<br>').append($('<small>').text('Pre-quarantine Authentication Result: ').addClass('text-muted').append($originalAuthResult));
            }else{
                $quarantineLI.append('<br>').append($('<small>').text('No pre-quarantine authentication header found').addClass('text-muted fst-italic'));
            }
        }
        $UI.output.securityAnalysisUL.append($quarantineLI);
    }else{
        $UI.output.securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>X-Forefront-Antispam-Report</code> header found'));
    }

    // next the bulk mail header
    if(DATA.securityReport.bulkMailReportHeaderSpecified){
        const $bulkMailScoreLI = $('<li>').addClass('list-group-item').html('<strong>Bulk Mail Filter:</strong> ');
        const $bcl = $('<span>').html('<span class="badge">BCL <span class="code font-monospace"></span></span> <span class="meaning text-muted"></span>');
        const bclDesc = bclMeaning(DATA.securityReport.bulkMailScore);
        $('.code', $bcl).text(DATA.securityReport.bulkMailScore);
        $('.meaning', $bcl).text(bclDesc);
        if(bclDesc === 'not from bulk mail sender' || bclDesc.includes('few user complaints')){
            $('.badge', $bcl).addClass('bg-success');
        }else if(bclDesc.includes('some user complaints')){
            $('.badge', $bcl).addClass('bg-warning');
        }else if(bclDesc.includes('many user complaints')){
            $('.badge', $bcl).addClass('bg-danger');
        }else{
            $('.badge', $bcl).addClass('bg-secondary');
        }
        $bulkMailScoreLI.append($bcl);
        $UI.output.securityAnalysisUL.append($bulkMailScoreLI);
    }else{
        $UI.output.securityAnalysisUL.append($('<li>').addClass('list-group-item list-group-item-warning').html('<i class="bi bi-exclamation-triangle-fill"></i> no <code>X-Microsoft-Antispam</code> header found'));
    }

    // end with the details to submit the mail to Microsoft for review
    if(DATA.canonicalByID.x_ms_exchange_organization_network_message_id.value){
        const $submitToMSLI = $('<li>').addClass('list-group-item list-group-item-info')
        $submitToMSLI.html(`<i class="bi bi-info-circle"></i> If this mail was mishandled by Micorosft's filters you can submit it for review using the Network Message ID <code>${DATA.canonicalByID.x_ms_exchange_organization_network_message_id.value}</code>. <a href="https://security.microsoft.com/reportsubmission?viewid=admin" rel="nofollow" target="_blank" class="btn btn-outline-primary btn-sm">Submit to MS <i class="bi bi-box-arrow-up-right"></i></a>`);
        $UI.output.securityAnalysisUL.append($submitToMSLI);
    }
}

/**
 * Render the *Custom Headers* card.
 */
 function renderCustomHeadersCard(){
    // empty the list
    $UI.output.customHeadersUL.empty();
    if(DATA.customPrefix.length > 0){
             if(DATA.listMatchingCustomPrefix.length > 0){
                for(const header of DATA.listMatchingCustomPrefix){
                    $UI.output.customHeadersUL.append(generateHeaderLI(header));
                }
             }else{
                 $UI.output.customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-info').html(`<i class="bi bi-info-circle-fill"></i> No headers pre-fixed with <code>${DATA.customPrefix}</code> found`));
             }
    }else{
        $UI.output.customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-info').html('<strong><i class="bi bi-info-circle-fill"></i> No custom prefix specified</strong> — enter a prefix in the form to spotlight matching headers'));
    }
}