FROM ubuntu:18.04

#ENV http_proxy http://user:password@host:port
#ENV https_proxy http://user:password@host:port

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

# Install getitintocrits.
RUN git clone https://github.com/IntegralDefense/getitintocrits.git \
    && ln -s /eventsentry/external/getitintocrits/bin/getitintocrits.py /usr/local/bin/getitintocrits.py \
    && ln -s /eventsentry/external/getitintocrits/bin/build_relationships.py /usr/local/bin/build_relationships.py
COPY ./app/conf/local/giic_config.ini /etc/getitintocrits/config.ini
COPY ./app/conf/local/giic_patterns.ini /etc/getitintocrits/patterns.ini

# Install splunklib.
RUN git clone https://github.com/IntegralDefense/splunklib.git \
    && ln -s /eventsentry/external/splunklib/splunk.py /usr/local/bin/splunk.py
COPY ./app/conf/local/splunklib.ini /root/.splunklib.ini
RUN chmod 600 /root/.splunklib.ini

# Install cbinterface config
COPY ./app/conf/local/credentials.response /etc/carbonblack/credentials.response

# Install pypy3.
RUN wget https://bitbucket.org/pypy/pypy/downloads/pypy3.5-v7.0.0-linux64.tar.bz2 \
    && tar jxvf pypy3.5-v7.0.0-linux64.tar.bz2 \
    && rm -rf pypy3.5-v7.0.0-linux64.tar.bz2 \
    && ln -s /eventsentry/external/pypy3.5-v7.0.0-linux64/bin/pypy3 /usr/local/bin/pypy3 \
    && pypy3 -m ensurepip \
    && pypy3 -m pip install --upgrade pip \
    && rm /usr/bin/python3 \
    && ln -s /usr/local/bin/pypy3 /usr/bin/python3
ENV PATH="/eventsentry/external/pypy3.5-v7.0.0-linux64/bin/:${PATH}"
ENV PYTHONWARNINGS=ignore::yaml.YAMLLoadWarning

# Set up the app directory.
WORKDIR /eventsentry/app

# Install the PIP packages.
COPY requirements.txt requirements.txt
RUN pypy3 -m pip install -r requirements.txt

# Install the app.
COPY . /eventsentry

#ENTRYPOINT ["dumb-init", "/eventsentry/app/sentry.py"]
#ENTRYPOINT ["/eventsentry/app/sentry.py"]
CMD ["/eventsentry/app/sentry.py"]