FROM debian:stable-slim

LABEL MAINTAINER Rui Fernandes <ruipedro16@protonmail.com>

ENV DEBIAN_FRONTEND=noninteractive

ARG USERNAME=sphincsplus_jasmin

ARG JASMIN_COMMIT=e84c0c59b4f4e005f2be4de5fdfbcaf1e3e2f975
ARG JASMIN_COMPILER_COMMIT=252e602bd76606942d6e1b2aa7d44eb4d09f1712 # corresponding extracted sources on gitlab.com (builds faster)

RUN apt-get -q -y update && apt-get -q -y upgrade && \
    apt-get -q -y install apt-utils sudo wget build-essential curl opam git m4 libgmp-dev libpcre3-dev \
                  pkg-config zlib1g-dev cvc4 vim gcc clang openssl libssl-dev && \
    apt-get -q -y clean

RUN echo "%sudo  ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/sudoers && \
    chown root:root /etc/sudoers.d/sudoers && \
    chmod 0400 /etc/sudoers.d/sudoers && \
    useradd -ms /bin/bash -d /home/$USERNAME -g root -G sudo -u 1001 $USERNAME

USER $USERNAME
WORKDIR /home/$USERNAME

RUN curl -L https://nixos.org/nix/install > nix-install && \
    sh nix-install && \
    (USER=$USERNAME; . /home/$USERNAME/.nix-profile/etc/profile.d/nix.sh) && \
    rm nix-install

RUN git clone https://gitlab.com/jasmin-lang/jasmin-compiler.git && \
    cd jasmin-compiler/ && \
    git checkout ${JASMIN_COMPILER_COMMIT}

RUN USER=$USERNAME; . /home/$USERNAME/.nix-profile/etc/profile.d/nix.sh && \
    cd jasmin-compiler/compiler && \
    nix-shell --command "make" && \
    sudo install -D jasminc /usr/local/bin/

RUN git clone https://github.com/jasmin-lang/jasmin.git && \
    cd jasmin/ && \
    git checkout ${JASMIN_COMMIT} && \
    mkdir -p /home/$USERNAME/.config/easycrypt/ && \
    echo "[general]\nidirs = Jasmin:/home/$USERNAME/jasmin/eclib" > /home/$USERNAME/.config/easycrypt/easycrypt.conf

RUN echo "eval $(opam env)" >> /home/$USERNAME/.bashrc

USER $USERNAME
RUN git clone --recurse-submodules https://github.com/tfaoliveira/sphincsplus-jasmin.git
