// ----------------------------------------------------------------------------
// UI Helper Functions 
// ----------------------------------------------------------------------------
// Functions for rendering the UI, these functions should be called by event
// handlers within theUI.

//
// === UI Utility Functions ===
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

/**
 * Generate a basic header list item. Both the header title and value are
 * rendered in a monospaced font.
 * 
 * The returned object will contain placeholder inline elements for the
 * header's name and value. These elements will have the classes
 * `.header-name` & `.header-value` respectively.
 * 
 * @param {HeaderObject} header
 */
function generateHeaderLI(header){
    const $ans = $('<li class="list-group-item"><code class="header-name"></code><br><span class="font-monospace header-value"></span></li>');
    $('.header-name', $ans).text(header.name);
    $('.header-value', $ans).text(header.value);
    return $ans;
}

//
// === Form Validation Functions ===
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
// === Output Rendering Functions ===
//

//
// -- Rendering Functions --
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
 * Render the highlighted custom headers card, if any.
 */
function renderCustomHeaders(){
    // empty the list
    $UI.output.customHeadersUL.empty();
    if(DATA.customPrefix.length > 0){
             if(DATA.listMatchingCustomPrefix.length > 0){
                for(const header of DATA.listMatchingCustomPrefix){
                    $UI.output.customHeadersUL.append(generateHeaderLI(header));
                }
             }else{
                 $UI.output.customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-warning').html(`<i class="bi bi-exclamation-triangle-fill"></i> found no headers pre-fixed with <code>${DATA.customPrefix}</code>`));
             }
    }else{
        $UI.output.customHeadersUL.append($('<li>').addClass('list-group-item list-group-item-info').html('<strong><i class="bi bi-info-circle-fill"></i> No custom prefix specified</strong> — enter a prefix in the form to spotlight matching headers'));
    }
}

/**
 * Render the *Basics* card.
 */
function renderBasicsCard(){
    // empty the UL containing the data
    $UI.output.basicsUL.empty();

    // LEFT OFF HERE - need function to get a header value for a single-valued header thay may or may not be present

    // $UI.output.basicsUL.append(generateHeaderLI({name: 'Subject', value: headers.subject ? headers.subject.value : ''}).addClass('fw-bold'));
    //     $basicsUL.append(generateBasicsLI('Date', headers.date? headers.date.value : 'UNKNOWN'));
    // $basicsUL.append(generateBasicsLI('From', headers.from ? headers.from.value : 'UNKNOWN').addClass('fw-bold'));
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
}