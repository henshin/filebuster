#!/usr/bin/perl
# install dependencies:
# > cpan -T install YAML Furl Benchmark Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper URI::URL Cache::LRU IO::Async::Timer::Periodic IO::Async::Loop
# -T skips all the tests which makes the install process very quick. Don't use this option if you encounter problems in the installation.

#TODO: 
#   - DNS over SOCKS is not currently working 
#   - when the initial request returns 302, quit and warn the user or perform follow redirects on every request
#   - create a seperate file with the list of ignored directories when using recursive search
#   - when limiting the line size, it would be a nice feature to read the columns from "stty size" command and adjust the number of chars accordingly

use strict;
use warnings;
use IO::Socket::Socks::Wrapper{}; # for SOCKS - should be invoked before other uses
use Data::Dumper;
use Getopt::Long qw(:config no_ignore_case);
use File::Basename qw(dirname fileparse);
use URI::Escape;
use HTML::Entities;
use List::MoreUtils qw(uniq); 
use Term::ANSIColor;
use threads;
use threads::shared;
use Time::HiRes qw(usleep);
use Benchmark;
use Net::DNS::Lite qw(inet_aton);
use Furl;
use Net::DNS;
use Cache::LRU;
#use IO::Socket;
use Socket;
use IO::Socket::SSL; # for SSL
use URI::URL;
use POSIX;
use IO::Async::Timer::Periodic;
use IO::Async::Loop;



#Constants
use constant DEF_MAXNUMTHREADS	=> 3;
use constant DEF_TIMEOUT		=> 5;
use constant DEF_NUMRETRIES		=> 2;
use constant DEF_PATTERN		=> '.';
use constant DEF_HIDECODE		=> "404";
use constant DEF_HTTPMETHOD		=> "GET";

my $program;
($program = $0) =~ s#.*/##;
my $fullpath = (defined(readlink($0))) ? readlink($0) : $0;
my ($filename, $dir, $suffix) = fileparse($fullpath);
#$dir will contain the directory of the filebuster script. We can use this to deduct the wordlist directory.
my $defaultwordlist = "$dir/wordlists/fast.txt";

print <<'EOF';
 ___________.__.__        __________                __                
 \_   _____/|__|  |   ____\______   \__ __  _______/  |_  ___________ 
  |    __)  |  |  | _/ __ \|    |  _/  |  \/  ___/\   __\/ __ \_  __ \
  |     \   |  |  |_\  ___/|    |   \  |  /\___ \  |  | \  ___/|  | \/
  \___  /   |__|____/\___  >______  /____//____  > |__|  \___  >__|   
      \/                 \/       \/           \/            \/    v0.9.5 
                                       HTTP fuzzer by Henshin (@henshinpt)
EOF

my $url;
my @wordlistfiles;
my $pattern=DEF_PATTERN;
my $maxnumthreads=DEF_MAXNUMTHREADS;
my $hidecode=DEF_HIDECODE;
my $outputfilename=undef;
my $help;
my $timeout=DEF_TIMEOUT;
my $maxretries=DEF_NUMRETRIES;
my $caseinsensitive;
my $nourlencoding;
my $hidelength;
my $hidestring;
my $debug;
my $proxy;
my $socks;
my $delay;
my $force;
my $extensions="";
my $cookies;
my $sslversion;
my $customheaders;
my $shortnamelist;
my $hidestringheaders;
my $quiet = 0;
my $stdoutisatty = 1;
my $recursive;
my $extensionsfilename = undef;
my $method = DEF_HTTPMETHOD;

GetOptions (
	'u=s' => \$url, 
	'w=s{,}' => \@wordlistfiles, 
	'p=s' => \$pattern, 
	'i' => \$caseinsensitive,
	't=i'=>\$maxnumthreads, 
	'hc=s' => \$hidecode,
	'hl=s' => \$hidelength,
	'hs=s' => \$hidestring,
	'hsh=s' => \$hidestringheaders,
	'o=s' => \$outputfilename,
	'help' => \$help,
	'h' => \$help,
	'timeout=i' => \$timeout,
	'retries=i' => \$maxretries,
	'cookies=s' => \$cookies,
	'nourlenc' => \$nourlencoding,
	'debug' => \$debug,
	'x=s' => \$proxy,
	's=s' => \$socks,
	'delay=i' => \$delay,
	'f' => \$force,
	'e=s' => \$extensions,
	'r' => \$recursive,
	'sslversion=s' => \$sslversion,
	'headers=s' => \$customheaders,
	'shortnamelist=s' => \$shortnamelist,
	'q' => \$quiet,
	'E=s' => \$extensionsfilename,
	'm=s' => \$method,
	) or exit(-1);

if($help){
	print <<EOF;
    Arguments:
        -u <url>:               Specifies the URL to analyze. Use the tag {fuzz} to indicate the location 
                                where you want to inject the payloads. If ommited, it will be appended to the
                                end of specified URL automatically
                                Example: http://www.website.com/files/test{fuzz}.php
        -w <path>:              Specifies the path to the wordlist(s). This can be either the path to a 
                                single file or multiple files using wildcards. Example: /home/user/*.txt. 
                                If not specified, it will attempt to locate and load the fast.txt wordlist 
                                automatically
        -p <pattern>:           Regex style pattern to filter specific words from the selected wordlists. 
                                If you use special regex characters like the pipe (|) remember to enclose 
                                the parameter in quotes. Example: '^(sha|res)'
        -t <num>:               Maximum number of threads to use. If you use more than 3 threads, you'll 
                                probably start flooding the web server with traffic. 3 threads
                                should provide a very fast request rate without not many errors. 
                                Default: 3 threads
        -f:                     Force FileBuster to proceed with the attack even if the initial request 
                                returns error code 500
        -e:                     Try additional file extensions. This will be appended after the {fuzz} payload.
                                You can specify multiple extensions separeted by comma. Example: xml,html
        -E:                     New-line separated file of extensions to be appended.
        -r:                     Use recursive scans. This is only possible if your {fuzz} keywork is at the end 
                                of your URL. Recursive scans respect the -p (pattern) filter if specified
        -m: <HTTP method>       Specifies a different HTTP method to use. Default is GET. Note that if you use 
                                HEAD, it will affect the performance. Also note that if you change to POST, you
                                should also add the Content-Type header using the --headers argument
        -x <ip:port>            Use specified proxy. Example: 127.0.0.1:8080 or http://192.168.0.1:8123
        -s <ip:port>            Use specified SOCKS proxy. Example: 127.0.0.1:8080. Please note that the DNS 
                                requests are not currently sent via the SOCKS proxy (library limitation) 
        -o <logfile>:           Specifies the log file to store the output. Default is /tmp/filebuster.log
        -i:                     Specifies case insensitive pattern searches
        --hc <code>:            Hides responses with the specified HTTP code. If not specified, Filebuster will
                                filter 404 codes by default. You can specify multiple codes seperated by comma. 
                                Examples: 301,302
        --hl <string>:          Hides responses with the specified length(s) on the HTTP response. You can 
                                specify multiple lengths seperated by comma. Example: 12105,0,100 
        --hs <string>:          Hides responses with the specified string/regex on the HTTP response
        --hsh <string>:         Hides responses with the specified string/regex on the HTTP headers
        --timeout <secs>:       Timeout period for the requests. Default: 10 seconds
        --retries <num>:        Maximum number of retries per request. FileBuster will attempt to perform 
                                the number of retries specified to confirm if it's indeed an error or a 
                                false positive. Default: 2 retries
        --delay <msecs>:        Delays each request in the specified number of milliseconds (single threaded)
        --nourlenc              Disables the URL encoding of the payloads. The default is to use encoding   
        --cookies <string>:     Sends the specified cookies with the requests. You can specify multiple
                                cookies seperated by semi-colon, following the HTTP standard.
                                Example: "cookiename1=value1; cookiename2=value2"  
        --headers <string>:     Sends additional headers in the HTTP requests. These should be specified in 
                                the format "header1=value1\\r\\nheader2=value2". Use '\\r\\n' to separate headers
        --sslversion <ver>:     Specify a fixed version of SSL to use. <ver> can be one of SSLv2, SSLv3, 
                                TLSv1, TLSv1_1 or TLSv1_2 
        --shortnamelist <file>: Experimental! This feature is useful if the site you are scanning is vulnerable 
                                to the IIS shortname vulnerability. You can provide a file with the partial 
                                filenames and Filebuster will attempt to automatically guess the fullname based 
                                on the dictionary provided. The file should have one partial filename per line 
                                and should look like ABCDEF~1. Filebuster will cut off everything after the ~1 
                                and use that as a search pattern on the dictionaries provided. 
        --debug                 This will output the contents of each HTTP response to the logfile
        -q:                     Quiet mode - Filebuster won't show the urls beeing scanned
        -h, --help:             This screen

EOF
	exit 0;
}

# Detect if stdout is a TTY.
$stdoutisatty = 0 unless (-t STDOUT);
# Assume quiet and don't print the URLs being scanned when stdout is not a TTY.
$quiet = 1 unless $stdoutisatty;

#for queued printing
my $semaphore :shared;

#DNS Cache
$Net::DNS::Lite::CACHE = Cache::LRU->new(
	size => 3,
);

#Validations
if(!$url){
	die "[-] Arguments missing. Use $program --help for instructions\n\n";
}

if( scalar @wordlistfiles == 0){
	# last try to load the default wordlist
	if(-e $defaultwordlist){
		print "[!] No wordlists were chosen. Using the default one: $defaultwordlist\n";
		push @wordlistfiles, $defaultwordlist;
	}else{
		die "[-] No wordlist was specific and couldn't find the default Filebuster's wordlists. Please specify wordlist manually using -w. \n\n";
	}
}

if(defined($hidecode)){
	if($hidecode !~ /^[\d,]*$/){
		die "[-] Invalid value for argument --hc. Only numbers and commas allowed\n\n";
	}
	$hidecode = "404,$hidecode" if($hidecode ne DEF_HIDECODE); # always filter 404s
}

#format the url properly
$url = "http://$url" if($url !~ /^https?:\/\//);
my $urlobj = new URI::URL($url);
my ($scheme, $user, $password, $host, $port, $epath, $eparams, $equery, $frag) = $urlobj->crack;
my $netloc = $urlobj->netloc;

if($url !~ /{fuzz}/){ # append the {fuzz} if not specified
	$url = "$url/" if ($url !~ /\/$/);
	$url = $url."{fuzz}";
}

#check recursive
if($url !~ /\/\{fuzz}$/ && defined($recursive)){
	die "[-] You can't use recursive scans if your {fuzz} keyword is not at the end of your URL\n\n";
}

#Proxy validations:
if(defined($socks)){
	if($socks !~ m/^([\d\.]+):(\d+)$/){
		die "[-] Invalid SOCKS argument. Please use syntax IP:PORT\n\n";
	}
	my $socksip = $1;
	my $socksport = $2;
	IO::Socket::Socks::Wrapper->import({
		ProxyAddr => $socksip, 
		ProxyPort => $socksport,
		SocksResolve => 1,
	});
}else{
	#disable socks
	IO::Socket::Socks::Wrapper->import(0);
	if (defined($proxy)){
		$proxy = "http://$proxy" if($proxy !~ /^https?:\/\//);
		if($proxy !~ m/^https?:\/\/([\d\.]+):(\d+)$/){
			die "[-] Invalid Proxy argument. Valid syntaxes are: IP:PORT or http://IP:PORT or https://IP:PORT\n\n";
		}
	}
}

#this only works if SOCKS is not being used. 
#theres no way to make this work with proxies. marked for deletion. Connection testing must rely on the first request sent only.

#my $addr = inet_ntoa(inet_aton($host))  or die "Can't resolve $host: $!\n";
#die("[-] Cannot resolve hostname. Verify if your URL is well formed and that you have connectivity.\n\n") if(!defined($addr));


# Build list of extensions from a file.
if (defined($extensionsfilename)) {
	open(my $fh, "<", $extensionsfilename) or die "[-] Error opening $extensionsfilename: $!\n\n";
	$extensions = do {
		local($/);
		<$fh>
	};
	close($fh);
	$extensions =~ s/\n/,/g;	# Replace each new-line with a comma.
	$extensions =~ s/^,//g;		# Remove initial empty line.
	$extensions =~ s/,,//g;		# Remove empty lines.
	$extensions =~ s/,$//;		# Drop the new-line from the last line.
}

#start benchmark timer
my $t0 = Benchmark->new;

#open log file
open OUTPUT, '>>', $outputfilename or die $! if (defined($outputfilename));

#Process start
&LogPrint("[+] ---- Session Start ----\n");
&LogPrint("[+] Start Time '" . strftime("%F %T", localtime) . "'\n");
&LogPrint("[+] Targetting URL '$url'\n");
&LogPrint("[+] Using Proxy '$proxy'\n") if ($proxy);
&LogPrint("[+] Using SOCKS proxy '$socks'\n") if ($socks);
if($delay){
	&LogPrint("[+] Waiting $delay milliseconds between requests\n") if ($delay);
	if($maxnumthreads != 1){
		&LogPrint( "[!] ");
		&PrintColor('bright_yellow', "Warning: ");
		&LogPrint("The delay parameter was specified. Number of threads will be reduced to 1\n");
		$maxnumthreads=1;
	}
	$delay *=1000; #converting from micro
}
&LogPrint("[+] Using $maxnumthreads simultaneous threads\n") if ($maxnumthreads != DEF_MAXNUMTHREADS);
if(scalar @wordlistfiles == 1){
	&LogPrint("[+] Wordlist used: ".$wordlistfiles[0]."\n");
}else{
	&LogPrint("[+] Multiple files specified for wordlist: ".scalar @wordlistfiles." files\n");
}
&LogPrint("[+] Pattern for words used: $pattern\n") if ($pattern ne DEF_PATTERN);
&LogPrint("[+] Using case insensitive searches on patterns\n") if ($caseinsensitive);
&LogPrint("[+] Using recursive scan\n") if ($recursive);
&LogPrint("[+] Shortname list file provided. Case insensitive searches will be used\n") if (defined($shortnamelist));
&LogPrint("[+] Using additional extensions from file: $extensionsfilename\n") if (defined($extensionsfilename));
&LogPrint("[+] Using additional extensions: $extensions\n") if ($extensions);
&LogPrint("[+] Hiding pages with response code(s): $hidecode\n") if ($hidecode ne DEF_HIDECODE);
&LogPrint("[+] Hiding pages with response length(s): $hidelength\n") if (defined $hidelength);
&LogPrint("[+] Hiding pages with string '$hidestring' in response body\n") if (defined($hidestring));
&LogPrint("[+] Hiding pages with string '$hidestringheaders' in response headers\n") if (defined($hidestringheaders));
&LogPrint("[+] Log will be saved to: $outputfilename\n") if (defined($outputfilename));
&LogPrint("[+] Timeout period set to $timeout seconds\n") if ($timeout != DEF_TIMEOUT);
&LogPrint("[+] Maximum number of retries set to $maxretries\n") if ($maxretries != DEF_NUMRETRIES);
&LogPrint("[+] URL encoding disabled\n") if ($nourlencoding);
&LogPrint("[+] Using $method HTTP method\n") if ($method ne DEF_HTTPMETHOD);
&LogPrint("[+] Indexing words...\n");
$|++; #autoflush buffers


my @allwords;
#TODO: fix bad bad bug when using {fuzz}word -e .aspx for example
foreach my $wordfile (@wordlistfiles){
	&PrintSequence("\e[K", "[*] Indexing file: $wordfile\r");
	if(defined($shortnamelist)){
		#print "\n\nShorname list: $shortnamelist\n";
		my @shortnamesfiles = &ReadFileShortnames($shortnamelist);
		$pattern = '^(';
		for(my $i=0; $i<(scalar @shortnamesfiles); $i++){
			$pattern.=$shortnamesfiles[$i];
			$pattern.='$' if (length($shortnamesfiles[$i])<6); 
			$pattern.='|' if(($i+1) != scalar @shortnamesfiles);
		}
		$pattern .= ')';
		#activate auto case insensitive searches
		$caseinsensitive=1;
		#print "Pattern: $pattern\n";
	}
	push @allwords, &ReadFile($wordfile,$pattern);
}

@allwords = uniq @allwords;
#just load the url without any word as well
unshift @allwords, '';

&PrintSequence("\e[K", "[+] All words indexed. Total words scrapped: " . scalar @allwords. "\n");
$|--;

if(!$nourlencoding){
	for my $word (@allwords){
		if($word=~/[%\/]/){
			#&LogPrint ("[!] ");
			#&PrintColor('bright_yellow', "Warning: ");
			&LogPrint("[+] Special characters will be encoded using smart encoding\n"); 
			last;
		}
	}
}
if(scalar @allwords == 0){
	die "[-] No words found with the specified regex filter.\n\n";
}

my %httpheaders;
#this would save some bandwidth but it affects speed.
#$httpheaders{'Accept-Encoding'}='gzip';

#set the Accept header because some sites require it
$httpheaders{'Accept'} = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

if($cookies){
	$httpheaders{'Cookie'}= "$cookies";
}

if($customheaders){
	my @headers = split /\\r\\n/, $customheaders;
	foreach my $header (@headers){
		my @namevalue = split /=/, $header;
		$httpheaders{$namevalue[0]}=$namevalue[1];
	}
}

my @httpheaders = %httpheaders; #because we need an ARRAY ref in FURL

my %sslopts = (
	'SSL_verify_mode' => SSL_VERIFY_NONE(),
	'SSL_cipher_list' => "ECDHE-RSA-AES128-SHA256,ECDHE-RSA-AES256-SHA384,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-AES128-SHA256,ECDHE-ECDSA-AES256-SHA384,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384", #WAF Bypass based on 0x09AL research (https://0x09al.github.io/waf/bypass/ssl/2018/07/02/web-application-firewall-bypass.html)
	'SSL_honor_cipher_order' => 0,
);

$sslopts{"SSL_version"} = $sslversion if ($sslversion);

my %furlargs = (
	#'inet_aton' => \&Net::DNS::Lite::inet_aton,
	'inet_aton' => sub { Net::DNS::Lite::inet_aton(@_) },
	# this works but there's a problem when using SOCKS proxies
	'get_address' => sub {
			#custom cached DNS resolution - Only 1 DNS per scan
            my ($host, $port, $timeout) = @_;
			#print "HOST: $host PORT: $port TIMEOUT: $timeout \n";
			my $addr = inet_aton(( $host =~ s/:\d+$//rg )); #this gets called many times throughout the scan. it shouldn't hurt the performance since it's not performing DNS requests, just translating to binary
			pack_sockaddr_in($port, $addr);#inet_aton($host,$timeout));
        },
	'timeout'   => 3,
	'agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0',
	'max_redirects' => 0,
	ssl_opts => \%sslopts,
	'headers' => \@httpheaders,
);
$furlargs{"proxy"} = $proxy if ($proxy);

#removed the IP address resolution because it wasn't possible to retrieve it through socks
print "[*] Testing connection to the website host '$host' ...\n";
my $sessionpayload = "$scheme://$netloc/";
my %ret = &SubmitGet($sessionpayload);
if($ret{"httpcode"} == 500){
	if(lc($scheme) eq "https"){
		print "[-] WAF bypass didn't work. Retrying with fallback ciphers\n";
		%sslopts = (
			'SSL_verify_mode' => SSL_VERIFY_NONE(),
			'SSL_cipher_list' => ".", 
			'SSL_honor_cipher_order' => 1,
		);
		%ret = &SubmitGet($sessionpayload);
	}
	if($ret{"httpcode"} == 500){
		if(!$force){
			print "[-] Could not connect to the website. Verify if the host is reachable and the web services are up!\n";
			if($ret{"msg"}){
				print "[!] Details: " . $ret{"msg"} . "\n" if $ret{"msg"};
				if($ret{"msg"} =~ /sslv3/i){
					print "[*] Note: It seems that the error is related to SSLv3. A possible workaround is to try to use the '--sslversion SSLv3' flag to force filebuster to use that version.\n";
				}
			}
			print "[!] Note: If this was expected, you can use the flag -f (Force) to force FileBuster to continue anyway.\n";
			print "\n";
			exit -1;
		}else{
			print "[!] Website returned error 500. Since the parameter -f (Force) was specified, FileBuster will continue anyway...\n";
			print "[!] Results with code 500 will be filtered from output automatically\n";
		}
	}
}
print "[+] Connected successfuly - Host returned HTTP code ${ret{'httpcode'}}\n\n";
print "[CODE] [LENGTH] [URL]\n";

my @paths:shared=();
my $path;
my @running = ();
my @joinable = ();
my @threadlists=();
my $totaldone:shared = 0;


threads->create(\&CountProgress) unless $quiet;

do{
	$path = shift(@paths);
	#only enters the if below when recursive && not the first pass
	if(defined($path) && $path ne ""){ 
		$url = $path."{fuzz}";
	}
	#Work splitter
	for(my $j=0; $j<scalar(@allwords); $j++){
		my $word = $allwords[$j];
		$word =~ s/\r|\n//g;
		#try to be intelligent about what to escape. This is a bit experimental. Note the inital ^ which negates the regex
		$word=uri_escape($word,'^A-Za-z0-9\-\._~&\$\+,\\\/:;=?@%'); 
		#escape the percent symbol under certain conditions
		$word =~ s/%(?=([^0-9A-Fa-f])|([0-9A-Fa-f][^0-9A-Fa-f]))/%25/g;
		$sessionpayload = $url;
		$sessionpayload =~ s/{fuzz}/$word/;
		my $arrayindex = $j % $maxnumthreads;
		push @{$threadlists[$arrayindex]}, $sessionpayload;
	}

	for(my $i=0; $i<$maxnumthreads && $i<scalar(@threadlists); $i++){
		#my @argarray = $threadlists[$i];
		threads->create(\&SubmitGetList, $i);
	}

	@running = threads->list(threads::running);
	@joinable = threads->list(threads::joinable);
	#my $remainingthreads = scalar @running;

	while (scalar(threads->list()) > 0) {
		@joinable = threads->list(threads::joinable);
		foreach my $thr (@joinable) {
			if ($thr->is_joinable()) {
				$thr->join;
				
			}
		}
	}
	@threadlists=();
}while($recursive && scalar(@paths));

&PrintSequence("\e[K", "[+] All threads finished!\n");
my $t1 = Benchmark->new;
my $td = timediff($t1,$t0);
print "[+] Execution time: ",timestr($td),"\n\n";
&LogPrint("[+] End Time '" . strftime("%F %T", localtime) . "'\n\n");
close OUTPUT if (defined($outputfilename));

exit 0;

#################################### FUNCTIONS #########################################

sub CountProgress{
	my $current = 0;
	my $loop = IO::Async::Loop->new();
	my $totalcount = scalar(@allwords);
	my $timer = IO::Async::Timer::Periodic->new(
		interval => 1/2,
		on_tick => sub {
			$|++;
			&PrintSequence("\e[K", "[ Speed: ".($totaldone - $current)." RPS / Progress: ". ceil($totaldone/$totalcount*100) ."%% ]\r");
			$current = $totaldone;
			$|--;
			$loop->stop if($totaldone eq $totalcount);
	});
	$timer->start;
	$loop->add( $timer );
	$loop->run;
}


sub SubmitGet{
	my($url) = @_;
	#print "PROXY is $proxy  URL is $url\n";
	#if($use_proxy && $proxy){
	#	print "proxy confirmation!\n";
	#	$furlargs{"proxy"} = $proxy;
	#}
	my $furl = Furl::HTTP->new(%furlargs);
	#print Dumper $furl;
	my ($minor_version, $code, $msg, $headers, $body) = $furl->request(
		'method' => 'GET',
		'url' => $url,
	);
	my %rethash = (
		"httpcode" => $code, 
		"headers" => $headers, 
		"content" => $body, 
		"payload" => $url, 
		"msg" => $msg, 
		"length" => length($body)
	);
	&Log("HTTP/1.1 $code $msg\n\n$body\n") if $debug;
	return (%rethash);
}

sub SubmitGetList{
	my($index) = @_;
	my @urllist = @{$threadlists[$index]};

	my $furl = Furl::HTTP->new(%furlargs);
	my $reqcount = 0;

	#TODO: make this more user configurable
	my %recursiveignorelist = map { $_ => 1} (
		"img",
		"images",
		"imgs",
		"image",
		"css",
		"web-inf",
		"meta-inf",
		"js",
		"javascript",
		"jscript",
		"icons",
		"style",
		"styles",
		"aspnet_client",
		"jquery",
		"yui",
		"themes",
		"fonts",
		"skins",
	);
	
	my @dirlistpatterns = (
		'<title>Index of \/.*?<\/title>', # Apache & nginx
		'<a href="\/.*?">\[To Parent Directory\]<\/a>', # IIS
		'<h\d>Directory listing for \/.*?<\/h\d>', # Python SimpleHTTPServer
	);

	#this will be used to analyze previous requests and make actions according to certain responses
	my @respqueue;
	my $respqueuesize = 3;
	foreach my $url(@urllist){
		$reqcount++;
		{
			#this is necessary to acurately update the progress
			lock $semaphore;
			$totaldone++;
		}
		&Log("**********************************************************\n") if $debug;
		&Log(" >  REQUEST: $url\n") if $debug;
		&Log("**********************************************************\n") if $debug;
		my $numretry=0;
		my ($minor_version, $code, $msg, $headers, $body);
		
		
		#make threads more resilient if errors happen
		eval {
			do{
				
				($minor_version, $code, $msg, $headers, $body) = $furl->request(
					'method' => $method,
					'url' => $url,
				);
				
				&usleep($delay) if $delay;
				$numretry++;
			}while($code==500 && $numretry<=$maxretries); 
			1;
		} or do {
			my $e = $@;
			chomp($e);
			$e =~ s#(.*?) at .?/.+#$1#; #hide line details
			&PrintSequence("\e[K");
			&PrintColor('bold white', '[');
			&PrintColor('bright_magenta', "ERR");
			&PrintColor('bold white', ']');
			printf("   %-7s  %-80s\n", "0", "$url  ($e)");
			next;
		};
		my %ret = (
			"httpcode" => $code, 
			"headers" => $headers, 
			"content" => $body, 
			"msg" => $msg, 
			"length" => length($body),
		);
	
		#convert the headers array to hash
		my %headers = @{$ret{"headers"}};
		#update length if it comes in the header
		#if ($headers{"content-length"}){
		#	$ret{"length"}=$headers{"content-length"};
		#}
		&Log("HTTP/1.1 $code $msg\n") if $debug;
		my $isqueued = undef;
		
		if(exists($headers{"location"})){
			#simple directory recursion detection
			my $value = $headers{"location"};
			my $modurl = $url;
			$modurl .= "   -->   " .$value;
			my $endpath = $value;
			$endpath =~ s#.*/(.+)/#$1#;
			if($recursive && $value eq "$url/" &&
					!( exists $recursiveignorelist{ lc($endpath) })){ 
				push(@paths,"$url/");
				$isqueued = 1;
			}
			$url = $modurl;
		}
		&Log("\n$body\n\n") if $debug;
		#filter the common error responses without details
		next if ((($ret{"length"} == 0) || ($ret{"length"} == 226)) && $ret{"httpcode"} == 400); #Apache
		next if ($ret{"length"} =~ /18\d/ && $ret{"httpcode"} == 400); #Nginx on Ubuntu but should cover other OSs too
		
		next if (defined $hidestringheaders && grep(/$hidestringheaders/i, @{$ret{"headers"}})>0);
		next if (defined $hidestring && $ret{"content"} =~ /$hidestring/);
		next if (defined $force && $ret{"httpcode"} == "500");
		#next if (defined $hidelength && $ret{"length"} == $hidelength);
		if (defined $hidelength){
			my @hidelengths = split(/,/, $hidelength);
			next if (grep(/^$ret{"length"}$/,@hidelengths)>0);
		}
		if (defined $hidecode){
			my @hidecodes = split(/,/, $hidecode);
			my $skip = undef;
			next if (grep(/^$ret{"httpcode"}$/,@hidecodes)>0);
		}

		{
			my $color = 'reset';
			$color = 'bright_green'		if($ret{"httpcode"} =~ /2\d\d/);
			$color = 'bright_yellow' 	if($ret{"httpcode"} =~ /3\d\d/);
			$color = 'bright_red' 		if($ret{"httpcode"} =~ /4\d\d/);
			$color = 'bright_cyan' 		if($ret{"httpcode"} =~ /401/);
			$color = 'bright_magenta' 	if($ret{"httpcode"} =~ /5\d\d/);

			#preventing threads from output prints at the same time
			lock($semaphore);
			&PrintSequence("\e[K");
			&PrintColor('bold white', '[');
			&PrintColor($color, $ret{"httpcode"});
			&PrintColor('bold white', ']');
			
			#add error details if we receive 500 error
			if($ret{"httpcode"} == 500){
				my $errmsg = $ret{"msg"};
				$errmsg =~ s#(.*?) at .?/.+#$1#; #hide line details
				chomp($errmsg); 
				$url .= " :: $errmsg";
			}
			my $str = sprintf("   %-7s  %-80s ", $ret{"length"}, $url);
			print $str;
			#Check for directory listing
			if($ret{"httpcode"} == 200){
				foreach my $pattern (@dirlistpatterns){
					if($ret{"content"} =~ /$pattern/i){
						&PrintColor('bold white', '[');
						&PrintColor('bright_yellow', "Directory listing");
						&PrintColor('bold white', ']');
					}
				}
			}
			if($isqueued){
				&PrintColor('bold white', '[');
				&PrintColor('bright_yellow', "QUEUED");
				&PrintColor('bold white', ']');
			}
			print "\n";
			$str = "[".$ret{"httpcode"}."]   $str\n";
			&Log($str);
		}
	}
}


sub Log{
	my $msg = $_[0];
	print OUTPUT "$msg" if (defined($outputfilename));
}

sub LogPrint{
	my $msg = $_[0];
	print "$msg";
	print OUTPUT "$msg" if (defined($outputfilename));
}

sub ReadFile{
	my ($file,$pattern) = @_;
	my @content;
	if(-z $file || !open(FILE,'<', $file)){
		if(scalar @allwords == 0){
			die("[-] Error: Can't open the file '$file'! ($!)\n\n");
		}else{
			&LogPrint("[-] Warning: Can't open the file '$file'! ($!) - Skipping...\n");
			return @content; #empty array
		}
	}
	chomp($extensions);	
	my @exts = split(/,/,$extensions);
	@exts = map { ".".$_ } @exts;
	unshift @exts, ""; # add a dummy null extension

	while( my $line = <FILE>){
		$line=~s/\r|\n//g;
		next if (!$line);
		next if ($line=~/^#/);
		foreach my $ext (@exts){
			if($caseinsensitive){
				$line = lc $line;
				push @content,"$line$ext" if($line =~ /$pattern/i);
			}else{
				push @content,"$line$ext" if($line =~ /$pattern/);
			}
		}
	}
	close (FILE);
	return @content;
}

sub ReadFileShortnames{
	my ($file) = @_;
	my @words;
	if(-z $file || !open(FILE,'<', $file)){
		die("[-] Error: Can't open the file '$file'! ($!)\n\n");
	}

	while( my $line = <FILE>){
		$line=~s/\r|\n//g;
		next if (!$line);
		next if ($line=~/^#/);
		$line =~ s/^(File|Dir):\s*//gi;  #filtering shortname scanner output
		#$line =~ s/ --.*//g
		$line =~ s/~\d.*//g; #filtering shortname scanner output
		#$line =~ s#([\(\)\[\]\$\^])#\\1#g; # escaping regex from list
		$line = quotemeta($line); #proper regex escaping (needs some testing)
		push @words,$line;
	}
	close (FILE);
	@words = uniq @words;
	return @words;
}

# Prints the given color is connected to a TTY, outputs the provided message and
# resets the attributes.
sub PrintColor{
	my ($color, $msg) = @_;

	print color("$color") if $stdoutisatty;
	print $msg;
	print color('clear') if $stdoutisatty;
}

# Only output the given message if not in quiet mode.
sub PrintQuiet{
	my ($seq, @msg) = @_;
	&PrintSequence($seq, @msg) unless $quiet;
}

# Prints the given character sequence if the character is connected to a TTY,
# followed by the message.
sub PrintSequence{
	my ($seq, @msg) = @_;

	print "$seq" if $stdoutisatty;
	printf @msg if @msg;
}
