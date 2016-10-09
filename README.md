# filebuster
An extremely fast and flexible web fuzzer

### Why another fuzzer?

My main motivation was to write a script that would allow me to fuzz a website based on a dictionary but that allowed me to filter words on that dictionary based on regex patterns. This necessity came from the frustration of trying to find the pages from the partial results returned by the Soroush's IIS shortname scanner tool (https://github.com/irsdl/iis-shortname-scanner/). 
In case that you're not aware of, most IIS web servers version 7.5 or below are vulnerable to filenames partial name discovery by requesting those pages in the format 8.3, for example: abcdef~1.zip

Many times I had results like getpag~1.asp, where you can clearly see that the page filename must be "get" followed by a word started with "pag".
This gets very easily done on Filebuster:
```
# perl filebuster.pl -u http://yoursite.com/get{fuzz}.asp -w /path/to/wordlist.txt -p ^pag
```

Initially Filebuster was just this, a fuzzer with regex support but then I really invested some time on it to support various interesting features while keeping it blazing fast.

### Why is it so fast?
Filebuster was built based on one of the fastest HTTP classes in the world (of PERL) - Furl::HTTP. Also the thread modelling is a bit optimized to run as fast as possible.

### Features
It packs a ton of features like:
 - The already mentioned Regex patterns
 - Multithreaded optimizations
 - Supports HTTP/HTTPS/SOCKS proxy
 - Allows for multiple wordlists using wildcards
 - Additional file extensions
 - Adjustable timeouts and retries
 - Adjustable delays / throtteling
 - Hide results based on HTTP code, length or words in headers or body
 - Support for custom cookies 
 - Support for custom headers
 - Supports multiple versions of the TLS protocol
 - Automatic TTY detection
 - Recursive scans
 
### Requisites
Perl version **5.10** is required

Filebuster resources a lot of features to third party libraries. However they can be easily installed with the following command:
```
# cpan install YAML Furl Switch Benchmark Cache::LRU Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper
```

### Installation
Filebuster is a Perl script so no installation is necessary. However, the best way of using filebuster is by creating a soft link on a directory that is included in the path. For example:
```
# ln -s /path/to/filebuster.pl /usr/local/bin/filebuster
```

### Syntax
On the most basic form, Filebuster can be run using the following syntax:
```
# perl filebuster.pl -u http://yoursite.com/ -w /path/to/wordlist.txt
```
If you want to fuzz the final part of the URL, then you don't need to using the tag **{fuzz}**  to indicate where to inject. 

A more complex example: 
```
# perl filebuster.pl -u http://yoursite.com/{fuzz}.jsp -w /path/to/wordlist.txt -t 3 -x http://127.0.0.1:8080 --hs "Error"
```
This would allow you to fuzz a website with 3 threads to find JSP pages, using a local proxy and hiding all responses with "Error" in the body.

Here's the full help:
```
# ./filebuster.pl --help
 ___________.__.__        __________                __                
 \_   _____/|__|  |   ____\______   \__ __  _______/  |_  ___________ 
  |    __)  |  |  | _/ __ \|    |  _/  |  \/  ___/\   __\/ __ \_  __ \
  |     \   |  |  |_\  ___/|    |   \  |  /\___ \  |  | \  ___/|  | \/
  \___  /   |__|____/\___  >______  /____//____  > |__|  \___  >__|   
      \/                 \/       \/           \/            \/    v0.8.7 
                                                  HTTP scanner by Henshin 
 
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
                                the format "header1=value1\r\nheader2=value2". Use '\r\n' to separate headers
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
```
As you can see the help screen is quite informative with examples for pretty much every option.

### TODO
Filebuster is a very nice tool but with your help, it can be even better. If you're into Perl and know a way of optimizing the performance of Filebuster, let me know. Right now it uses little memory but a lot of CPU power, so there's always room for improvement. 
Also right now I have these 4 things on my mind to check out once I have the time:
 - use File::Map to load dictionaries since it should be more memory efficient
 - when the initial request returns 302, quit and warn the user or perform follow redirects on every request
 - create a seperate file with the list of ignored directories when using recursive search
 - when limiting the line size, it would be a nice feature to read the columns from "stty size" command and adjust the number of chars accordingly. Right now the lenght is fixed and might not work for small terminals

### Thanks
I would like to thank TC for his updates to the code on the initial phase of the project 
