FROM perl:threaded

COPY . /filebuster/
WORKDIR /filebuster

RUN groupadd -g 999 filebuster
RUN useradd -r -u 999 -g filebuster -d /filebuster filebuster
RUN chown -R filebuster.filebuster /filebuster

RUN cpan -T install YAML Furl Benchmark Net::DNS Net::DNS::Lite List::MoreUtils IO::Socket::SSL URI::Escape HTML::Entities IO::Socket::Socks::Wrapper URI::URL Cache::LRU IO::Async::Timer::Periodic IO::Async::Loop

USER filebuster

ENTRYPOINT ["/usr/local/bin/perl","/filebuster/filebuster.pl"]
CMD ["--help"]
