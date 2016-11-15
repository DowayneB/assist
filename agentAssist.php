<?php
class dnsLib
{
    public function getNameServers($domain)
    {
        //get an array of name servers
        $ns = exec('dig ns '.$domain.' +short');

        if (!empty($ns)) {
            $nsCheck = dns_get_record($domain, DNS_NS);
            foreach ($nsCheck as $nsCheckIndex) {
                $nameServers[] = $nsCheckIndex['target'];
            }
        } else {
            $nameServers = FALSE;
        }
        $nameServers = NULL;
        $nameServers = array('ns.dns1.co.za','ns.dns2.co.za','ns1.wix.co.za','ns2.wix.co.za');
        return $nameServers;
    }
    public function getMxRecords($domain)
    {
        //get an array of MX records
        if (dns_get_record($domain, DNS_MX) != FALSE) {
            $mxCheck = dns_get_record($domain, DNS_MX);
            $count = 0;
            foreach ($mxCheck as $mxCheckIndex) {
                $details[$count]['priority'] = $mxCheckIndex['pri'];
                $details[$count]['target'] = $mxCheckIndex['target'];
                $count++;
            }
            sort($details);
        } else {
            $details[0] = FALSE;
        }
        return $details;
    }
    public function getRecordIp($record,$domain)
    {
        //get a string containing the IP
        if (dns_get_record($record.$domain, DNS_A) != FALSE) {
            $records = dns_get_record($record.$domain, DNS_A);
            $record = $records[0]['ip'];
            return $record;
        } else {
            $record = FALSE;
        }
        return $record;
    }
    public function getRecordNames($ip)
    {
        //get an array of names for the server
        // use exec, because get host name by IP will concat the results
        exec('dig -x '.$ip.' +short',$serverNames);
        //if more than one key, then remove .hosted as they are 'junk' ptr records, but only if there is more than 1 PTR.
        if(count($serverNames) > 1){
            $i = 0;
            foreach ($serverNames as $serverName){
                if (strpos($serverName,'.hosted.co.za.')){
                    unset($serverNames[$i]);
                }
                $i + 1;
            }
        }
        // reset the indexes of the array
        array_splice($serverNames,1,1);
        return $serverNames;

   }
    public function getPortStatus($destination,$port)
    {
        // check destination for port.
        // use this for specific ports on hosting and mail check, rather than check everything
        /**
         * handle timeout warning rather than suppress
         * http://php.net/manual/en/function.error-reporting.php
         * http://php.net/manual/en/function.set-error-handler.php
         */
        if (@fsockopen($destination, $port, $errno, $errstr, .2))
        {
            $status = 1;
        }  else {
            $status = 0;
        }
        return $status;
    }
    public function checkMxPorts($server)
    {
        $failures[0] = NULL;
        $smtp    = $this->getPortStatus($server,25);
        $smtpSSL = $this->getPortStatus($server,465);
        $smtpTLS = $this->getPortStatus($server,587);
        $imap    = $this->getPortStatus($server,143);
        $imapSSL = $this->getPortStatus($server,993);
        $pop     = $this->getPortStatus($server,110);
        $popSSL  = $this->getPortStatus($server,995);
        // for each failure, give the element the same name as the index. (for display purposes)
        if($smtp == FALSE){
            $failures['stmp'] = 'stmp';
        }
        if($smtpSSL == FALSE){
            $failures['stmpSsl'] = 'stmpSsl';
        }
        if($smtpTLS == FALSE){
            $failures['stmpTls'] = 'stmpTls';
        }
        if($imap == FALSE){
            $failures['imap'] = 'imap';
        }
        if($imapSSL == FALSE){
            $failures['imapSsl'] = 'imapSsl';
        }
        if($pop == FALSE){
            $failures['pop'] = 'pop';
        }
        if($popSSL == FALSE){
            $failures['popSsl'] = 'popSsl';
        }
        if($failures[0] == 0){
            $failures[0] = '';
        }

        return $failures;
    }
    public function checkMxRouting($domain){
        //get mxrecord
        $mxRecords = $this->getMxRecords($domain);
        //sort the mxrecords by priority
        function cmp($a, $b) {
            return $a['priority'] > $b['priority'] ? 1 : -1;
        }
        uasort($mxRecords, 'cmp');
        //check where the MX routes
        // return codes
        // 1 = no mx
        // 2 = ucebox
        // 3 = spambox
        // 4 = direct to server
        // 5 = Google
        // 6 = Outlook
        // 7 = Undetermined
        $mxRecord = $mxRecords[0]['target'];
        if($mxRecord == FALSE){
            $details['mailRoute'] = 1;
        }elseif(strpos($mxRecord,'ucebox')){
            $details['mailRoute'] = 2;
        }elseif(strpos($mxRecord,'spambox')){
            $details['mailRoute'] = 3;
        }elseif($mxRecord =='mail.'.$domain){
            $details['mailRoute'] = 4;
        }elseif(strpos($mxRecord,'google')){
            $details['mailRoute'] = 5;
        }elseif(strpos($mxRecord,'Outlook')){
            $details['mailRoute'] = 6;
        }else{
            $details['mailRoute'] = 7;
        }
        $details['check'][] = 'mail.'.$domain;
        $details['check'][] = $mxRecord;
        // check to see whether the A record is same as mail.
        $aRecord = $this->getRecordIp('',$domain);
        $mailRecord = $this->getRecordIp('mail.',$domain);
        if($aRecord == $mailRecord){
            $details['aIsRoutable'] = 1;
        }else{
            $details['aIsRoutable'] = 0;
        }
        switch($details['mailRoute']){
            case 1:
                // server has no MX record, A will be used
                $msgStart = 'This server has no MX record, so mail will be routed to the A record, ';
                $fping = exec('fping '.$domain);
                $msgEnd = '. '.$fping;
                if($details['aIsRoutable']){
                    // this is routing mail to the server
                    $details['routeToA'] = 1;
                    $details['message'] = $msgStart.'which is the same as the mail record, routing looks OK'.$msgEnd;
                    $details['result']['class'] = 1;
                    $details['result']['specification'] = 'OK';
                    $details['mailServer'] = $this->getRecordIp('',$domain);
                }else{
                    // this is not routing to mail server
                    $details['routeToA'] = 0;
                    $details['message'] = $msgStart.'which is not the same as the mail record, this is not OK'.$msgEnd;
                    $details['result']['class'] = 3;
                    $details['result']['specification'] = 'NOROUTABLE';
                    $details['mailServer'] = $this->getRecordIp('',$domain);
                }
                break;
            case 2:
                // server routes through ucebox check routing
                $msgStart = 'This mail routes through ucebox, ';
                $fping = exec('fping mail.'.$domain);
                $msgEnd = '. '.$fping;
                if($details['aIsRoutable']){
                    // if route is domain.tld:25 this is okay
                    $details['routeToA'] = 1;
                    $details['message'] = $msgStart.'routing should be OK'.$msgEnd;
                    $details['result']['class'] = 1;
                    $details['result']['specification'] = 'OK';
                    $details['mailServer'] = $mailRecord;
                }else{
                    // this needs to explicitly route to mail.domain
                    $details['routeToA'] = 0;
                    $details['message'] = $msgStart.'make sure route is set to mail.'.$domain.':25'.$msgEnd;
                    $details['result']['class'] = 2;
                    $details['result']['specification'] = 'CHECKROUTE';
                    $details['mailServer'] = $mailRecord;
                }
                break;
            case 3:
                // server routes through spambox check routing
                $msgStart = 'This mail routes through spambox, ';
                $fping = exec('fping mail.'.$domain);
                $msgEnd = '. '.$fping;
                if($details['aIsRoutable']){
                    // if route is domain.tld:25 this is okay
                    $details['routeToA'] = 1;
                    $details['message'] = $msgStart.'routing should be OK'.$msgEnd;
                    $details['result']['class'] = 1;
                    $details['result']['specification'] = 'OK';
                    $details['mailServer'] = $mailRecord;
                }else{
                    // this needs to explicitly route to mail.domain
                    $details['routeToA'] = 0;
                    $details['message'] = $msgStart.'make sure route is set to mail.'.$domain.':25'.$msgEnd;
                    $details['result']['class'] = 2;
                    $details['result']['specification'] = 'CHECKROUTE';
                    $details['mailServer'] = $mailRecord;
                }
                break;
            case 4:
                // routing to mail.domain.tld no routing check
                $fping = exec('fping mail.'.$domain);
                $msgEnd = '. '.$fping;
                $details['routeToA'] = 1;
                $details['message'] = 'This mail goes directly to mail.'.$domain.'.'.$msgEnd;
                $details['result']['class'] = 1;
                $details['result']['specification'] = 'OK';
                $details['mailServer'] = $mailRecord;
                break;
            case 5:
                // this is connected to Google mail
                $details['routeToA'] = 0;
                $details['message'] = 'This mail routes through Google';
                $details['result']['class'] = 2;
                $details['result']['specification'] = 'EXTERNAL';
                $details['mailServer'] = 'Google';
                break;
            case 6:
                // this is connected to Outlook Mail
                $details['routeToA'] = 0;
                $details['message'] = 'This mail routes through Outlook';
                $details['result']['class'] = 2;
                $details['result']['specification'] = 'EXTERNAL';
                $details['mailServer'] = 'Outlook';
                break;
            default:
                $details['routeToA'] = 0;
                $details['message'] = 'We were unable to determine how this mail works.';
                $details['result']['class'] = 2;
                $details['result']['specification'] = 'EXTERNAL';
                $details['mailServer'] = 'Unknown';
        }
        $nonRoutables = array('Unknown','Google','Outlook');
        if(!in_array($details['mailServer'],$nonRoutables)){
            // check the port status of the mail server
            $mxPortStatus = $this->checkMxPorts($details['mailServer']);
        }else{
            $mxPortStatus[0] = 'NRMX'; // non routable MX
        }
        $details['portscheck'] = $mxPortStatus;
        $result['class'] = $details['result']['class'];
        $result['specification'] = $details['result']['specification'];
        $result['mailServer'] = $details['mailServer'];
        $result['failedPorts'] = $details['portscheck'];
        $result['message'] = $details['message'];
        //return $result;
        return $result;
    }
    public function checkNsIssues($domain)

    {
        // first check whether DNS has propagated.
        // check the records between the IDC name servers as well as Google.
        $nameServers = $this->getNameServers($domain);
        if ($nameServers != FALSE){
            /** code **/
        $idcResult = $this->getRecordIp('', $domain);
        $googleResult = json_decode(file_get_contents('https://dns.google.com/resolve?name=' . $domain));
        if (array_key_exists('Answer', $googleResult)) {
            $googleResult = $googleResult->{'Answer'}[0]->{'data'};
        } else {
            $googleResult = 0;
        }
        // check if our NS and google return the same value
        if ($googleResult == $idcResult) {
            $propagated = 1;
            $nsReturn['return'] = 200;
            $nsReturn['returnMessage'][] = 'DNS seems propagated between the IDC and Google\'s name servers';
        } else {
            $propagated = 0;
            $nsReturn['return'] = 100;
            $nsReturn['returnMessage'][] = 'DNS is not fully propagated between the IDC and Google\'s name servers';
        }
        // if our NS is present, they should be the only NS. if not get warning.
        $ahNameServers = array('ns.dns1.co.za', 'ns.dns2.co.za', 'ns.otherdns.com', 'ns.otherdns.net');
        if (count(array_intersect($nameServers, $ahNameServers)) > 0) {
            // one of our name servers is present, so all must exist
            $nsCount = count($nameServers);
            if ($nsCount != 4) {
                //not all our name servers are present, find out if less or more
                if ($nsCount > 4) {
                    // there are more name servers
                    /** return warning that there are mixed name servers */
                    $nsResult = 'NSMIXED';
                    $nsReturn['return'] = 500;
                    $nsReturn['returnMessage'][] = 'There are mixed name servers';
                } else {
                    //check if all name servers are ours
                    if (array_intersect($nameServers, $ahNameServers)) {
                        /** return warning that not all our name servers are confgured */
                        $nsResult = 'NSSHORT';
                        $nsReturn['return'] = 300;
                        $nsReturn['returnMessage'][] = 'Not all 4 of our name servers are configured';

                    } else {
                        /** return warning that there are mixed name servers */
                        $nsResult = 'NSMIXED';
                        $nsReturn['return'] = 500;
                        $nsReturn['returnMessage'][] = 'There are mixed name servers';
                    }
                }
            } else {
                if (count(array_intersect($nameServers, $ahNameServers)) == $nsCount) {
                    //our name servers are all that are present
                    /** everything is okay with name servers */
                    $nsResult = 'NSOKAY';
                    $nsReturn['return'] = 200;
                    $nsReturn['returnMessage'][] = 'Everything looks good with the name servers, all 4 are configured';
                } else {
                    /** there are mixed name servers */
                    $nsResult = 'NSMIXED';
                    $nsReturn['return'] = 500;
                    $nsReturn['returnMessage'][] = 'There are mixed name servers';
                }
            }
        } else {
            // none of our name servers are present.
            // see which DNS is active
            // do some more research on how these namservers actually look.
            $ns1 = $nameServers[0];
            if (strpos($ns1, 'wix')) {
                /** the website is with wix */
                $nsResult = 'WIX';
                $nsReturn['return'] = 300;
                $nsReturn['returnMessage'][] = 'This domains name servers are Wix name servers, the MX may be a problem';
            } elseif (strpos($ns1, 'wordpress')) {
                /** the website is with wordpress */
                $nsResult = 'WORDPRESS';
                $nsReturn['return'] = 300;
                $nsReturn['returnMessage'][] = 'This domains name servers are Wordpress name servers, the MX may be a problem';
            } elseif (strpos($ns1, 'cloudflare')) {
                /** the website is going through cloudflare */
                $nsResult = 'CLOUDFLARE';
                $nsReturn['return'] = 300;
                $nsReturn['returnMessage'][] = 'This domains records are determined by Cloudflare, please check that records are pointing to the correct server';
            } else {
                /** this DNS is not handled by afrihost */
                $nsResult = 'ELSEWHERE';
                $nsReturn['return'] = 300;
                $nsReturn['returnMessage'][] = 'We are unable to tell who\'s name servers are configured, please either change the name servers, or ensure relevant records (especially MX) are set correctly';
            }
        }
        //check if SOA is ours.
        $soa = dns_get_record($domain, DNS_SOA);
        $soa = $soa[0]['rname'];
        if ($soa == 'support.afrihost.com') {
            /** our SOA answered */
            $soaResult = 'AFRIHOST SOA';
            $nsReturn['returnMessage'][] = 'The SOA is Afrihost';
        } else {
            /** there is another SOA present */
            $soaResult = 'OTHER SOA';
            $nsReturn['returnMessage'][] = 'The SOA is NOT Afrihost';
        }
        /** return errors based on checks */
        $nsReturn['propagation'] = $propagated;
        $nsReturn['nameservers'] = $nsResult;
        $nsReturn['soa'] = $soaResult;

    }else{
            $nsReturn['return'] = 500;
            $nsReturn['returnMessage'][] = 'This domain has no name servers';
        }
        return $nsReturn;
    }
    public function checkMxIssues($domain)
    {
        function portResult($failures){
            //status set to true on failure
            $status = 0;
            $list = null ;
            foreach ($failures as $failure){
                if($failure != null) {
                    $list .= $failure . ' ';
                }
            }
            if(!empty($list)){
                if(trim($list) == 'NRMX'){
                    $list = 'the MX is routed externally, so we do not check ports';
                    $mxReturn['return'] = 300;
                    $mxReturn['returnMessage'] = 'the MX is routed externally, so we do not check ports';
                }else {

                    $mxReturn['return'] = 500;
                    $mxReturn['returnMessage'] = 'the ports for ' . $list . 'have failed, clients may experience issues with their mail clients';
                }
            }else{
                $list = 'all ports okay';
                $mxReturn['return'] = 200 ;
                $mxReturn['returnMessage'] = 'all ports okay, mail clients should connect fine';
            }
            return $mxReturn;
        }

        $details = $this->checkMxRouting($domain);
        $failures = $details['failedPorts'];
        switch ($details['class']){
            case 1:
                $result = 'SUCCESS';
                $reason = $details['specification'];
                // check if port check succeeded.
                $mxReturn['return'] = 200;
                $mxReturn['returnMessage'][] = $details['message'];
                $portcheck = portResult($failures);
                $mxReturn['returnMessage'][] = $portcheck['returnMessage'];
                break;
            case 2:
                $result = 'WARNING';
                $reason = $details['specification'];
                // check if port check succeeded
                $mxReturn['return'] = 300;
                $mxReturn['returnMessage'][] = $details['message'];
                $portcheck = portResult($failures);
                $mxReturn['returnMessage'][] = $portcheck['returnMessage'];
                break;
            case 3:
                $result = 'ERROR';
                $reason = $details['specification'];
                $mxReturn['return'] = 500;
                $mxReturn['returnMessage'][] = $details['message'];
                $portcheck = portResult($failures);
                $mxReturn['returnMessage'][] = $portcheck['returnMessage'];
                break;
        }
        $mxCheck['return'] = $mxReturn['return'];
        $mxCheck['returnMessage'] = $mxReturn['returnMessage'];
        $mxCheck['mxResult'] = $result;
        $mxCheck['mxResultReason'] = $reason;
        $mxCheck['mxPortCheck'] = $portcheck;
        return $mxCheck;
    }
    public function checkHostingIssues($domain)
    {
        // perform hosting checks
        //check that www and a records match.
        $contentRecord['a']   = $this->getRecordIp(''    ,$domain);
        $contentRecord['www'] = $this->getRecordIp('www.',$domain);
        $contentRecord['ftp'] = $this->getRecordIp('ftp.',$domain);
        if (count(array_unique($contentRecord)) === 1){
            // all these records are the same
            $recordsEqual = 1;
            $ptrRecord = $this->getRecordNames($contentRecord['a']);
            $ptr = $ptrRecord[0];

            $serverType = 0;
            if(strpos($ptr,'aserv')){
                // this site is on a shared server
                $serverType = 'shared';
                $hostingReturn['returnMessage'][] = 'This domain is on a Shared server';
            }elseif (strpos($ptr,'dedicated')) {
                // this site is on a dedicated server
                $serverType = 'dedicated';
                $hostingReturn['returnMessage'][] = 'This domain is on a Dedicated server';
            }elseif (strpos($ptr,'vserv')){
                // this site is on a reseller server.
                $serverType = 'reseller';
                $hostingReturn['returnMessage'][] = 'This domain is on a reseller server';
            }else{
                $serverType = 'unknown';
                $hostingReturn['returnMessage'][] = 'This server\'s PTR records are neither .dedicated.co.za, .aserv.co.za, nor .vserv.co.za';
            }
            // check if server is pingable.

            $ping = exec('fping -t 500 '.$contentRecord['a']);


            set_time_limit(1);
            if(strpos($ping,'is alive')){
                $hostingReturn['returnMessage'][] = 'This server is responding to Ping';
                $pingResult = 1;
                // we can ping this server
                $port80 = $this->getPortStatus($contentRecord['a'],80);
                if($port80 == 1){
                    $hostingReturn['returnMessage'][] = 'Port 80 is open on this server';
                    $port80successful = 1;
                    // port 80 on this server is reachable
                    // can we get 200 when requesting headers?
                    $responseCode = get_headers('http://www.'.$domain);
                    $result = $responseCode[0];
                    if(strpos($result,'200')){
                        $result = '200';
                        $hostingReturn['return'] = 200;
                        $hostingReturn['returnMessage'][] = 'We got a 200 response header while fetching the web page';
                    }elseif (strpos($result,'30')){
                        $result = '300';
                        $hostingReturn['return'] = 500;
                        $hostingReturn['returnMessage'][] = 'We got redirected while trying to fetch the web page';
                    }elseif (strpos($result,'401')){
                        $result = '401';
                        $hostingReturn['return'] = 500;
                        $hostingReturn['returnMessage'][] = 'We are unauthorized to fetch this web page, please check permission';
                    }elseif (strpos($result,'403')){
                        $result = '403';
                        $hostingReturn['return'] = 500;
                        $hostingReturn['returnMessage'][] = 'Access to this web page is forbidden';
                    }elseif (strpos($result,'404')){
                        $result = '404';
                        $hostingReturn['return'] = 500;
                        $hostingReturn['returnMessage'][] = 'The web page was not found';
                    }elseif (strpos($result,'500')){
                        $result = '500';
                        $hostingReturn['return'] = 500;
                        $hostingReturn['returnMessage'][] = 'There was an internal server error';
                    }
                   // $port80successful $pingResult $serverType $recordsEqual
                    $hostingReturn['recordsEqual'] = $recordsEqual;
                    $hostingReturn['serverType'] = $serverType;
                    $hostingReturn['pingResult'] = $pingResult;
                    $hostingReturn['port80'] = $port80successful;
                    $hostingReturn['responseHeader'] = $result;
                }
            }else{
                // this server is not responding to pings
                $hostingReturn['recordsEqual'] = $recordsEqual;
                $hostingReturn['serverType'] = $serverType;
                $hostingReturn['pingResult'] = 'NOPING';
                $hostingReturn['port80'] = 'NOPING';
                $hostingReturn['responseHeader'] = 'NOPING';
                $hostingReturn['return'] = 500;
                $hostingReturn['returnMessage'][] = 'This server is not responding to Ping';
            }
        }else{
            // these records do not match.
            $hostingReturn['recordsEqual'] = 'NOTEQUAL';
            $hostingReturn['serverType'] = 'NOTEQUAL';
            $hostingReturn['pingResult'] = 'NOTEQUAL';
            $hostingReturn['port80'] = 'NOTEQUAL';
            $hostingReturn['responseHeader'] = 'NOTEQUAL';
            $hostingReturn['return'] = 500;
            $hostingReturn['returnMessage'][] = 'The www, ftp and non-www records do not match, please fix DNS';
        }
        return $hostingReturn;
    }

    public function checkIssues($domain){
        /*

        */
        $nsIssues = $this->checkNsIssues($domain);
        if($nsIssues['return'] != 500) {
            $mxIssues = $this->checkMxIssues($domain);
            $hostingIssues = $this->checkHostingIssues($domain);
        }
        print_r($nsIssues['return'].PHP_EOL);
        print_r($nsIssues['returnMessage']);
        if (isset($mxIssues)) {
            print_r($mxIssues['return'].PHP_EOL);
            print_r($mxIssues['returnMessage']);
        }else{
            print_r($nsIssues['return'].PHP_EOL);
            $message[] = 'There are problems with the name servers, MX could not be checked.';
            print_r($message);
        }
        if (isset($hostingIssues)) {
            print_r($hostingIssues['return'].PHP_EOL);
            print_r($hostingIssues['returnMessage']);
        }else{
            print_r($nsIssues['return'].PHP_EOL);
            $message[0] = 'There are problems with the name servers, hosting could not be checked.';
            print_r($message);
        }
    }
}

$dnsLib = new dnsLib();
$domain = $argv[1];
$dnsLib->checkIssues($domain);
