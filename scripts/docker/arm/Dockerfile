FROM ubuntu:20.04
MAINTAINER Tobias Hienzsch <post@tobias-hienzsch.de>
LABEL Description="Image for building and debugging arm-embedded projects from git"

WORKDIR /toolchain

# Install any needed packages specified in requirements.txt
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
# Development files
      build-essential \
      git \
      bzip2 \
      wget && \
    apt-get clean
RUN wget -qO- https://developer.arm.com/-/media/Files/downloads/gnu-rm/10.3-2021.07/gcc-arm-none-eabi-10.3-2021.07-x86_64-linux.tar.bz2 | tar -xj

ENV PATH "/toolchain/gcc-arm-none-eabi-10.3-2021.07/bin:$PATH"