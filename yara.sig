rule Blackhole_Gootkit
{
        meta:
                author = "X"
                version = "X"
                description = "Blackhole Gootkit"

        strings:
                $js = /\(\/\[\^A-.-.-9\\\\\+\\\\\/\\\\\=\]\/g,""\)\]\(\(.*?\),\(.*?\)\)/
        condition:
                $js
}

rule Blackhole_GootKit_deofuscated
{
        meta:
                author = "X"
                version = "X"
                description = "Blackhole_Gootkit_deofuscated"

        strings:
                $js = /"http:\/\/"\+domainName\+"\/runforestrun/
		$js1= /'http:\/\/'\+domainName\+'\/in.cgi/
        condition:
                $js or $js1 
}

rule Malicious_Redirect_Code
{
        meta:
                author = "X"
                version = "X"
                description = "Blackhole"

        strings:
                $js = /km0ae9gr6m/
		$js2=/qhk6sa6g1c/
		$js3=/\.php\?page=[a-zA-Z0-9]{16}/
		$js4=/iframe/
		$js5=/%69%66%72%61%6d%65/
		$js6=/%68%69%64%64%65%6e/
		$js7=/unescape/
		$js8=/<!\-\-68c8c7\-\->/
		$long=/([0-9]{1,4},){256}/
		$long2=/([0-9]{1,2}\.[0-9]{1,2}\$){8}/
		$long3=/([0-9]{1,4}\.\.[0-9]{1,4}){8}/
		$long4=/([0-9a-zA-Z]{1,2}(\$|@|#|!|,){1,2}){8}/
		$long5=/("[0-9a-zA-Z]{1,2}",){16}/
		$long6=/([0-9a-zA-Z]{2,3}&&){256}/
		$long7=/(0x[0-9a-fA-F]{1,2},){256}/
		$maliciousfor=/for\((.)=(.){1,10};(.){5}!=(.);(.)\+\+\)/
		$maliciousif=/if\('[a-zA-Z]{3,8}'=='[a-zA-Z]{3,8}'\)/
        condition:
                ($js and $js2) or ($long or $long2 or $long3 or $long4 or $long6) or ($js3 and $js4) or ($js5 and $js6 and $js7) or ($long5 and $maliciousfor) or $maliciousif or $js8 or $long7
}

