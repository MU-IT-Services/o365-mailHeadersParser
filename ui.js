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
 * Render the *Custom Headers* card, if any.
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