// Document ready handler
$.when( $.ready ).then(function() {
    const $parseBtn = $('button#parse_btn');
    const $spamReportTA = $('#spamReport-ta');

    // add form validation to the input
    $spamReportTA.on('input', ()=>{validateSpamReportTA($spamReportTA)}).trigger('input');

    // add an event handler to the parse button
    $parseBtn.click(()=>{
        const spamReport = parseSpamReportHeader(sanitiseMailHeader($spamReportTA.val()));
        const $out = $('<pre>').text(JSON.stringify(spamReport, null, 2));
        $('#output_div').empty().append($out);
    });
});

/**
 * Validate the spam report header input box.
 * 
 * @param {jQuery} $textArea - a jQuery object representing the text area to validate
 * @return {boolean}
 */
function validateSpamReportTA($textArea){
    if(isValidSpamReportHeader(sanitiseMailHeader($textArea.val()))){
        $textArea.removeClass('is-invalid').addClass('is-valid');
        $textArea.closest('form').find('button').prop('disabled', false);
        return true;
    }
    $textArea.removeClass('is-valid').addClass('is-invalid');
    $textArea.closest('form').find('button').prop('disabled', true);
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
 * Check if something is a plausible spam report header.
 * 
 * A header must be a single-line string that starts with
 * `X-Forefront-Antispam-Report:`
 * 
 * @param {string} input
 * @returns {boolean}
 */
function isValidSpamReportHeader(input){
    // make sure we have a string
    if(typeof input !== 'string') return false;

    // make sure the string starts with the expected text
    if(!input.startsWith('X-Forefront-Antispam-Report:')) return false;

    // make sure the string is a single line
    if(input.split(/\r\n|\r|\n/).length !== 1) return false;

    // if we got here all is well, so return true
    return true;
}

/**
 * Parse a sanitised Office365 Span Report Header.
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
function parseSpamReportHeader(input){
    if(typeof input !== 'string') throw new TypeError('must pass a string');
    if(!isValidSpamReportHeader(input)) throw new RangeError('must pass a sanitised header');

    // strip off the header name
    let headerVal = input.replace(/^X-Forefront-Antispam-Report:[ ]/, '');

    // break the header down into its parts
    const header = {};
    let headerFields = headerVal.split(';');
    for(const field of headerFields){
        if(field === '') continue;
        const fieldMatch = field.match(/^(\w+):(.*)$/)
        if(fieldMatch){
            header[fieldMatch[1]] = fieldMatch[2] ? fieldMatch[2] : true;
        }else{
            console.debug('failed to parse field', field);
        }
    }
    console.log(header);
    return {
        senderCountryCode: header.CTRY || '',
        senderIP: header.CIP || '',
        spamScore: parseInt(header.SCL) || -1
    };
}