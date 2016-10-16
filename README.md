# Filebuster
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
 - Supports HTTP/HTTPS/SOCKS proxy
 - Allows for multiple wordlists using wildcards
 - Additional file extensions
 - Adjustable timeouts and retries
 - Adjustable delays / throttling
 - Hide results based on HTTP code, length or words in headers or body
 - Support for custom cookies 
 - Support for custom headers
 - Supports multiple versions of the TLS protocol
 - Automatic TTY detection
 - Recursive scans
 - Integrated wordlists
 
### Requisites
Perl version **5.10** or higher is required

Filebuster resources a lot of features to third party libraries. However they can be easily installed with the following command:
```
# cpan install YAML Furl Switch Benchmark Cache::LRU Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper
```

### Installation
Filebuster is a Perl script so no installation is necessary. However, the best way of using filebuster is by creating a soft link on a directory that is included in the path. For example:
```
# ln -s /path/to/filebuster.pl /usr/local/bin/filebuster
```
Then you will be able to use it system wide

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

For the complete syntax help with examples, just run `filebuster.pl --help`.

### Wordlists
I've created some wordlists based on different sources around the web for your convenience. You can find them on the `wordlists` directory.
This means you can start using FileBuster right away:
```
# perl filebuster.pl -u http://yoursite.com/ -w wordlists/normal.txt
```
If you need more wordlists, you should check out the great [SecLists](https://github.com/danielmiessler/SecLists/) repository.

### TODO
Filebuster is a very nice tool but with your help, it can be even better. If you're into Perl and know a way of optimizing the performance of Filebuster, let me know. Right now it uses little memory but a lot of CPU power, so there's always room for improvement. 
Also right now I have these 4 things on my mind to check out once I have the time:
 - when the initial request returns 302, quit and warn the user or perform follow redirects on every request
 - create a separate file with the list of ignored directories when using recursive search
 - when limiting the line size, it would be a nice feature to read the columns from "stty size" command and adjust the number of chars accordingly. Right now the lenght is fixed and might not work for small terminals

### Thanks
I would like to thank TC for his updates to the code on the initial phase of the project 
