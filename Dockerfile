FROM perl:threaded

COPY . /filebuster/
WORKDIR /filebuster

RUN cpan -T install YAML Furl Benchmark Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper URI::URL Cache::LRU

ENTRYPOINT ["/usr/local/bin/perl","/filebuster/filebuster.pl"]
CMD ["--help"]
