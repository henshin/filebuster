#!/usr/bin/perl
# install dependencies (it can take a while):
# > cpan install YAML Furl Switch Benchmark Cache::LRU Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper

#TODO: 
#   - use File::Map to load files -> extreme memory optimization
#   - when the initial request returns 302, quit and warn the user or perform follow redirects on every request
#   - create a seperate file with the list of ignored directories when using recursive search
#   - when limiting the line size, it would be a nice feature to read the columns from "stty size" command and adjust the number of chars accordingly

use strict;
use warnings;
# nasty workaround to disable smartmatch experimental warning. Hopefully temporary
no if $] >= 5.017011, warnings => 'experimental::smartmatch';
use Data::Dumper;
use Getopt::Long qw(:config no_ignore_case);	# Stupid default behaviour.
use File::Basename qw(dirname);
use URI::Escape;
use HTML::Entities;
use List::MoreUtils qw(uniq); #requires cpan install
use Term::ANSIColor;
use Switch;
use threads;
use threads::shared;
use Time::HiRes qw(usleep);
use Benchmark;
use IO::Socket::SSL; # for SSL
use IO::Socket::Socks::Wrapper{}; # for SOCKS
#Japanese power - 75% increased performance over LWP::UserAgent!
use Furl;
use Cache::LRU;
use Net::DNS::Lite qw(inet_aton);

use Socket qw(pack_sockaddr_in inet_ntoa);
use URI::Split qw(uri_split);
use POSIX;

#Constants
use constant DEF_MAXNUMTHREADS	=> 2;
use constant DEF_TIMEOUT		=> 5;
use constant DEF_NUMRETRIES		=> 2;
use constant DEF_PATTERN		=> '.';
use constant DEF_HIDECODE		=> "404";

my $program;
($program = $0) =~ s#.*/##;

print <<'EOF';
 ___________.__.__        __________                __                
 \_   _____/|__|  |   ____\______   \__ __  _______/  |_  ___________ 
  |    __)  |  |  | _/ __ \|    |  _/  |  \/  ___/\   __\/ __ \_  __ \
  |     \   |  |  |_\  ___/|    |   \  |  /\___ \  |  | \  ___/|  | \/
  \___  /   |__|____/\___  >______  /____//____  > |__|  \___  >__|   
      \/                 \/       \/           \/            \/    v0.8.7 
                                                  HTTP scanner by Henshin 
 
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
	) or exit(-1);

if($help){
	print <<EOF;
    Arguments:
        -u <url>:               Specifies the URL to analyze. Use the tag {fuzz} to indicate the location 
                                where you want to inject the payloads. If ommited, it will be appended to the
                                specified URL automatically
                                Example: http://www.website.com/files/test{fuzz}.php
        -w <path>:              Specifies the path to the wordlist(s). This can be either the path to a 
                                single file or a path with shell 
                                wildcards for multiple files. Example: /home/user/*.txt
        -p <pattern>:           Regex style pattern to filter specific words from the selected wordlists. 
                                If you use special regex characters like the pipe (|) remember to enclose 
                                the parameter in quotes. Example: '^(sha|res)'
        -t <num>:               Maximum number of threads to use. If you use more than 3 threads, you'll 
                                probably start flooding the web server with traffic. 2 threads
                                should provide a very fast request rate without not many errors. 
                                Default: 2 threads
        -f:                     Force FileBuster to proceed with the attack even if the initial request 
                                returns error code 500
        -e:                     Try additional file extensions. This will be appended after the {fuzz} payload.
                                You can specify multiple extensions separeted by comma. Example: .xml,.html
        -E:                     New-line separated file of extensions to be appended.
        -r:                     Use recursive scans. This is only possible if your {fuzz} keywork is at the end 
                                of your URL. Recursive scans respect the -p (pattern) filter if specified
        -x <ip:port>            Use specified proxy. Example: 127.0.0.1:8080 or http://192.168.0.1:8123
        -s <ip:port>            Use specified SOCKS proxy. Example: 127.0.0.1:8080
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

#for queue printing
my $semaphore :shared;

#DNS Cache
$Net::DNS::Lite::CACHE = Cache::LRU->new(
	size => 256,
);
$Net::DNS::Lite::CACHE_TTL = 100; # this doesn't seem to affect DNS cache

#Validations
if(!$url || scalar @wordlistfiles == 0){
	die "[-] Arguments missing. Use $program --help for instructions\n\n";
}

if(defined($hidecode)){
	if($hidecode !~ /^[\d,]*$/){
		die "[-] Invalid value for argument --hc. Only numbers and commas allowed\n\n";
	}
}

#format the url properly
$url = "http://$url" if($url !~ /^https?:\/\//);
if($url !~ /{fuzz}/){ # append the {fuzz} if not specified
	$url = "$url/" if ($url !~ /\/$/);
	$url = $url."{fuzz}";
}

# DNS resolve
my ($scheme, $host, $urlpath, $query, $frag) = uri_split($url);

#remove port from host if specified
#$host =~ s/:\d+$//g;
my $addr = inet_aton(( $host =~ s/:\d+$//rg ));
#my $iphost  = gethostbyaddr($addr, AF_INET);
#print "Resolves to: $iphost\n";
die("[-] Cannot resolve hostname. Verify if your URL is well formed and that you have connectivity.\n\n") if(!defined($addr));
my $resolvedip = inet_ntoa($addr);

#die();
#check recursive
if($url !~ /\/\{fuzz}$/ && defined($recursive)){
	die "[-] You can't use recursive scans if your {fuzz} keyword is not at the end of your URL\n\n";
}

#Proxy validations:
if(defined($socks)){
	if($socks !~ m/^([\d\.]+):(\d+)$/){
		die "[-] Invalid SOCKS argument. Use syntax IP:PORT\n\n";
	}
	my $socksip = $1;
	my $socksport = $2;
	IO::Socket::Socks::Wrapper->import({ProxyAddr => $socksip, ProxyPort => $socksport});
}else{
	#disable socks
	IO::Socket::Socks::Wrapper->import(0);
	if (defined($proxy)){
		print "Using PROXY!";
		$proxy = "http://$proxy" if($proxy !~ /^https?:\/\//);
		if($proxy !~ m/^https?:\/\/([\d\.]+):(\d+)$/){
			die "[-] Invalid Proxy argument. Valid syntaxes are: IP:PORT or http://IP:PORT or https://IP:PORT\n\n";
		}
	}
}

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
	if($maxnumthreads != 1){
		&LogPrint("[!] Warning: The delay parameter was specified. Number of threads will be reduced to 1\n");
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
&LogPrint("[+] Waiting $delay milliseconds between requests\n") if ($delay);
&LogPrint("[+] Indexing words...\n");
$|++; #autoflush buffers


#if(defined($method)){
#	$method = "GET";
#}else{
#	$method = DEF_METHOD;
#}
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
&PrintSequence("\e[K", "[+] All words indexed. Total words scrapped: " . scalar @allwords. "\n\n");
$|--;

if(!$nourlencoding){
	for my $word (@allwords){
		if($word=~/[%\/]/){
			print "[!] ";
			&PrintColor('bright_yellow', "Warning: ");
			print "Special characters found on wordlist and the flag --nourlenc was not specified. Characters will be encoded for safe requests.\n"; 
			last;
		}
	}
}
if(scalar @allwords == 0){
	die "[-] No words found with the specified regex filter.\n\n";
}

#at this point we are sure to have a ip host to connect to 
#my $sessionpayload = $url;
#$sessionpayload =~ s/{fuzz}/\//;
#my $host;
#if($sessionpayload =~ m#(https?://)(.*?)/#){
#	$host = $2;
#}else{
#	die("[-] Couldn't extract the hostname from your URL. Are you sure you're inserting something like http://website.com/?\n\n");
#}

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


#print Dumper %httpheaders;
my @httpheaders = %httpheaders; #because we need an ARRAY ref in FURL

my %sslopts = (
	'SSL_verify_mode' => SSL_VERIFY_NONE()
);

$sslopts{"SSL_version"} = $sslversion if ($sslversion);


my %furlargs = (
	#'inet_aton' => \&Net::DNS::Lite::inet_aton,
	#'inet_aton' => sub { Net::DNS::Lite::inet_aton(@_) },
	'get_address' => sub {
			#custom cached DNS resolution - Only 1 DNS per scan
            my ($host, $port, $timeout) = @_;
			#print "HOST: $host PORT: $port TIMEOUT: $timeout\n";
			pack_sockaddr_in($port, $addr);#inet_aton($host,$timeout));
        },
	'timeout'   => 5,
	'agent' => 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0',
	'max_redirects' => 0,
	ssl_opts => \%sslopts,
	'headers' => \@httpheaders,
);
$furlargs{"proxy"} = $proxy if ($proxy);

if($proxy){
	print "[!] Proxy specified. Testing connection to proxy...\n";
	&SubmitGet("$proxy");
	#TODO: check proxy
}

print "[*] Testing connection to the website host '$host' ($resolvedip)...\n";

my $sessionpayload = "$scheme://$host/7ddf32e17a6ac5ce04a8ecbf782ca509.ext";
#instead of requesting a random file, why not just load the web root?
$sessionpayload = "$scheme://$host/";

my %ret = &SubmitGet($sessionpayload);
#my %ret = &SubmitGet($url);

print "[*] Web site returned ". $ret{"httpcode"}."\n";
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

}else{
	print "[+] Connected successfuly!\n\n";
}
print "[CODE] [LENGTH] [URL]\n";

my @paths:shared=();
my $path;
my @running = ();
my @joinable = ();
my @threadlists=();
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
		next if ($word =~ /^\s*$/);
		$word=uri_escape($word) if(!$nourlencoding);
		$sessionpayload = $url;
		$sessionpayload =~ s/{fuzz}/$word/;
#print "$sessionpayload\n";
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

sub SubmitGet{
	my($url,$use_proxy) = @_;
	#my %furlargs = (
	#	'inet_aton' => \&Net::DNS::Lite::inet_aton,
	#	'timeout'   => 5,
	#	'agent' => 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:27.0) Gecko/20100101 Firefox/27.0',
	#	'max_redirects' => 0,
	#);
	if($use_proxy && $proxy){
		$furlargs{"proxy"} = $proxy;
	}


	my $furl = Furl::HTTP->new(%furlargs);
	#print Dumper %furlargs;
	#print "Port: $port\n";
	my ($minor_version, $code, $msg, $headers, $body) = $furl->request(
		'method' => 'GET',
		'url' => $url,
	);
	#print $Net::DNS::Lite::CACHE->get("in a henshin.ovh");
	#print "IP: " ; print Net::DNS::Lite::inet_aton("www.google.com", 15);
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

	my @recursiveignorelist = [
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
	];

	#this will be used to analyze previous requests and make actions according to certain responses
	my @respqueue;
	my $respqueuesize = 3;

	foreach my $url(@urllist){
		#print $url,"\n";
		$|++; #autoflush buffers
		#if($reqcount % 50 == 0){ #less updates
			if(length($url)>100){
				&PrintQuiet("\e[K", "Scanning %.100s(...)\r",$url);
			}else{
				&PrintQuiet("\e[K", "Scanning %s\r",$url);
			}
		#}
		$|--;
		$reqcount++;
		&Log("**********************************************************\n") if $debug;
		&Log(" >  REQUEST: $url\n") if $debug;
		&Log("**********************************************************\n") if $debug;
		my $numretry=0;
		my ($minor_version, $code, $msg, $headers, $body);
		#make threads more resilient if errors happen
		eval {
			do{
				($minor_version, $code, $msg, $headers, $body) = $furl->request(
					'method' => "GET",
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
		#no need to iterate & parse headers
		#while (my($key, $value) = each(%headers)){
		if(exists($headers{"location"})){
			#simple directory recursion detection
			my $value = $headers{"location"};
			my $modurl = $url;
			$modurl .= "   -->   " .$value;
			my $endpath = $value;
			$endpath =~ s#.*/(.+)/#$1#;
			if($recursive && $value eq "$url/" && !(lc($endpath) ~~ @recursiveignorelist)){ 
				push(@paths,"$url/");
				$isqueued = 1;
			}
			$url = $modurl;
		}
		&Log("\n$body\n\n") if $debug;

		next if (defined $hidestringheaders && $ret{"headers"} ~~ /$hidestringheaders/i);
		next if (defined $hidestring && $ret{"content"} =~ /$hidestring/);
		next if (defined $force && $ret{"httpcode"} == "500");
		#next if (defined $hidelength && $ret{"length"} == $hidelength);
		if (defined $hidelength){
			my @hidelengths = split(/,/, $hidelength);
			my $skip = undef;
			foreach my $len (@hidelengths){
				if($ret{"length"} == $len){
					$skip = 1;
					last;
				}
			}
			next if ($skip);
		}
		if (defined $hidecode){
			my @hidecodes = split(/,/, $hidecode);
			my $skip = undef;
			foreach my $code (@hidecodes){
				if($ret{"httpcode"} == $code){
					$skip = 1;
					last;
				}
			}
			next if ($skip);
		}

		#push @respqueue, [$ret{"httpcode"},$ret{"length"}];
		#if(scalar(@respqueue)>=$respqueuesize){
		#	shift @resqueue; #remove the first element to limit the array to $resqueuesize
		#	my $lastcode,$lastlength;
		#	foreach my $resp (@respqueue){
		#		
		#	}
		#}
		
		
		{
			my $color = 'reset';
			switch($ret{"httpcode"}){
				case /2\d\d/ { $color = 'bright_green' }
				case /3\d\d/ { $color = 'bright_yellow' }
				case /4\d\d/ { $color = 'bright_red' }
				case /5\d\d/ { $color = 'bright_magenta' }
			}
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
				$url .= " :: $errmsg";
			}
			my $str = sprintf("   %-7s  %-80s ", $ret{"length"}, $url);
			print $str;
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
	#my $warnbadchars = undef;
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
	unshift @exts, ""; # add a dummy null extension

	while( my $line = <FILE>){
		$line=~s/\r|\n//g;
		next if (!$line);
		next if ($line=~/^#/);
		#if($line=~/[%\/]/){
		#	$warnbadchars=1;
		#}
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
	#if($warnbadchars && !$nourlencoding){
	#	print "[!] ";
	#	&PrintColor('bright_yellow', "Warning: ");
	#	print "Special characters found on wordlist and the flag --nourlenc was not specified. Characters will be encoded for safe requests.\n"; 
	#}
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
