// ----------------------------------------------------------------------------
// Page Setup & Event Handlers 
// ----------------------------------------------------------------------------
// The data structures used by the various event handlers, the event handlers
// themselves, and the document ready handler to tie everything together.

//
// === Global Variables =======================================================
//

/**
 * The data structure that will hold the headers once they are loaded.
 * 
 * @type {HeaderSet}
 */
let DATA = generateBlankHeaderSet();

//
// === The Document ready handler =============================================
//
$.when( $.ready ).then(function() {
    $UI.form.source = $('#fullHeaders-ta');
    $UI.form.customHeadersPrefix = $('#customHeadersPrefix-tb');
    $UI.form.parseDirectionRG = $('input[type="radio"][name="parseAs-rbg"]')
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
            newHeaders = parseSource($UI.form.source.val(), $UI.form.parseDirectionRG.filter(':checked').val(), $UI.form.customHeadersPrefix.val());
            console.debug(`successfully parsed source, found ${newHeaders.list.length} header(s)`, newHeaders);
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

        // show any parse warnings
        for(const w of DATA.warnings){
            showParseWarning(w);
        }

        // render the full header list
        renderAllHeaders();

        // render the full security report
        renderSecurityReport();

        // render the info cards
        renderBasicsCard();
        //renderSecurityReportCard();
        renderCustomHeadersCard();

    //     // render the full security report
    //     $securityReportDiv.empty();
    //     if(Object.keys(securityDetails).length > 0){
    //         const $securityReport = $('<pre>').addClass('json-container').append(prettyPrintJson.toHtml(securityDetails, {}));
    //         $securityReportDiv.append($securityReport);
    //     }else{
    //         $securityReportDiv.append($('<div>').addClass('alert alert-danger').html('<i class="bi bi-exclamation-octagon-fill"></i> No Secrity/Spam Headers Found!'));
    //     }

    //     

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