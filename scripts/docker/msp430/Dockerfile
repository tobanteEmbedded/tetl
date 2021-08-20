FROM ubuntu:20.04
MAINTAINER Tobias Hienzsch <post@tobias-hienzsch.de>

WORKDIR /toolchain

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y build-essential git bzip2 wget
RUN apt-get clean


RUN wget -qO- http://software-dl.ti.com/msp430/msp430_public_sw/mcu/msp430/MSPGCC/9_3_1_2/export/msp430-gcc-9.3.1.11_linux64.tar.bz2 | tar -xj
ENV PATH "/toolchain/msp430-gcc-9.3.1.11_linux64/bin:$PATH"