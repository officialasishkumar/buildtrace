# Census runner: a stock language image plus buildtrace and strace.
ARG BASE
FROM ${BASE}
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends strace >/dev/null && rm -rf /var/lib/apt/lists/*
COPY buildtrace-linux /usr/local/bin/buildtrace
COPY ip2asn-combined.tsv.gz /root/.cache/buildtrace/ip2asn-combined.tsv.gz
WORKDIR /work
