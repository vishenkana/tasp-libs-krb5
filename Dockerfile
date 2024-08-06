FROM tasp/libcommon:1.0.2

COPY . /krb5
WORKDIR /krb5

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && apt-get install -y --no-install-recommends --reinstall \
        libkrb5-dev

RUN mkdir build && cd build && cmake .. && ninja install
