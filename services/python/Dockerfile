FROM ubuntu:18.04

ARG http_proxy
ARG https_proxy

WORKDIR /eventsentry/

# Install the required packages.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
        dnsutils \
        dumb-init \
        gcc \
        geoip-bin \
        geoip-database \
        geoipupdate \
        git \
        libmagic-dev \
        libxml2-dev \
        libxslt-dev \
        locales \
        make \
        p7zip-full \
        python3 \
        python3-pip \
        tzdata \
        wget \
    && rm -rf /var/lib/apt/lists/*
COPY ./app/conf/local/GeoIP.conf /etc/GeoIP.conf

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Set up the external directory.
WORKDIR /eventsentry/external/

# Install proxychains-ng.
RUN git clone https://github.com/rofl0r/proxychains-ng.git \
    && cd proxychains-ng \
    && ./configure --prefix=/usr --sysconfdir=/etc \
    && make \
    && make install \
    && rm -rf /eventsentry/external/proxychains-ng
COPY ./app/conf/local/proxychains.conf /etc/proxychains.conf

# Install splunklib.
RUN git clone https://github.com/IntegralDefense/splunklib.git \
    && ln -s /eventsentry/external/splunklib/splunk.py /usr/local/bin/splunk.py
COPY ./app/conf/local/splunklib.ini /root/.splunklib.ini
RUN chmod 600 /root/.splunklib.ini

# Install cbinterface config
COPY ./app/conf/local/credentials.response /etc/carbonblack/credentials.response

# Set up the app directory.
WORKDIR /eventsentry/app

# Install the PIP packages.
COPY requirements.txt requirements.txt
RUN python3 -m pip install -r requirements.txt

# Install the app.
COPY . /eventsentry

#ENTRYPOINT ["dumb-init", "/eventsentry/app/sentry.py"]
#ENTRYPOINT ["/eventsentry/app/sentry.py"]
CMD ["/eventsentry/app/sentry.py"]
