# Filebuster
An extremely fast and flexible web fuzzer

### What is it?
Filebuster is a HTTP fuzzer / content discovery script with loads of features and built to be easy to use and fast! It uses one of the fastest HTTP classes in the world (of PERL) - Furl::HTTP. Also the thread modelling is optimized to run as fast as possible.

### Features
It packs a ton of features like:
 - Regex patterns on wordlists
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
 - Integrated wordlists with custom payloads
 - Automatic smart encoding
 - Automatic filtering of results

Filebuster is updated often. New features will be added regularly.

## Running the Perl script

Perl version **5.10** or higher is required

FileBuster resources a lot of features to third party libraries. However they can be easily installed with the following command:

```bash
cpan -T install YAML Furl Benchmark Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper URI::URL Cache::LRU IO::Async::Timer::Periodic IO::Async::Loop
```

The `-T` option will make the installation much quicker but if you run into problems, remove it to allow CPAN to perform the tests per package.

### Installation

Filebuster is a Perl script so no installation is necessary. However, the best way of using Filebuster is by creating a soft link on a directory that is included in the path. For example:

```bash
ln -s /path/to/filebuster.pl /usr/local/bin/filebuster
```

Then you will be able to use it system wide

## Packaged Binary

Because installing all the dependencies is sometimes not possible, I'm providing a pre-packed binary with all the dependencies built in. It works even on slim Linux distributions. This was achieved by using Perl Packer `pp`. You can download it from the Releases section.

If you don't trust my binary, you can pack the binary yourself on a system which contains all the Perl dependencies and then move that binary to other systems. You will need `pp` command line tool and some libraries. Here's how to do it:
```bash
sudo apt update
sudo apt install cpanminus build-essential libperl-dev libssl-dev zlib1g-dev
```
Install Perl dependencies:
```bash
sudo cpan install -T PAR::Packer YAML Furl Benchmark Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper URI::URL Cache::LRU IO::Async::Timer::Periodic IO::Async::Loop Net::SSLeay
```
Now you should be able to execute `pp` and pack your `filebuster` binary:
```bash
pp -o filebuster -l libssl.so.1.1 -l libcrypto.so.1.1 -M "IO::Async::Loop::**" -M "Metrics::Any::Adapter::**" -M "IO::Async::Internals::**" filebuster.pl 
```
## Syntax
On the most basic form, Filebuster can be run just using the following syntax:
```bash
filebuster -u http://yoursite/ 
```
If you want to fuzz the final part of the URL, then you don't need to using the tag `{fuzz}`  to indicate where to inject. 

The wordlist parameter (`-w`) is not mandatory as from version 0.9.1. If not specified, Filebuster will attempt to find and load the "Fast" wordlist automatically. 

### Most common arguments

* `-w` - Paths to wordlists to use. You can specify a list here and FileBuster will automatically ignore duplicates. e.g. `-w wordlist1.txt ../morewordlists/*.txt`
* `--hc` - hides the specified responses codes. E.g. `--hc 403,400`
* `--hs` - hides responses which contain string in the response body. e.g. `--hs "does not exist"`
* `--hsh` - hides responses which contain string in the headers. Useful to ignore redirects to login pages, for example. e.g. `--hsh "login.aspx"`
* `-e` - FileBuster will try every entry in the wordlist with the provided extensions as well. e.g. `-e aspx,ashx,asmx`

For the complete syntax help with examples, just run `filebuster --help`.

A more complex example: 
```bash
filebuster -u http://yoursite/{fuzz}.jsp -w /path/to/wordlist.txt -t 3 -x http://127.0.0.1:8080 --hs "Error"
```
This would allow you to fuzz a website with 3 threads to find JSP pages, using a local proxy and hiding all responses with "Error" in the body.

## Running in docker

You'll need to start by building the container:
```bash
docker build -t filebuster .
```

Afterwards, you can run it like this:
```bash
docker run -ti --init --rm filebuster -u http://yoursite/
```

If you need to use custom wordlists, remember to map the file, e.g.:
```bash
docker run -ti --init --rm -v /path/to/wordlist.txt:/filebuster/mywordlist.txt filebuster -u http://yoursite/ -w /filebuster/mywordlist.txt
```

You can create an alias in your shell, and make it (almost) seamless:
```bash
alias filebuster="docker run -ti --init --rm filebuster"
```

You can now just run it:
```bash
filebuster -u http://yoursite/
```

## Wordlists

I've created some wordlists based on different sources around the web together with my own custom payloads that I've came across during my pentests and research. You can find them on the `wordlists` directory.
If you need more wordlists, you should check out the great [SecLists](https://github.com/danielmiessler/SecLists/) repository.

## Contribute

If you have any issues or suggestions feel free to get in touch. 


