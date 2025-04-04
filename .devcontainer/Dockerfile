FROM mcr.microsoft.com/devcontainers/go:1-1.23-bookworm

USER vscode

RUN sudo apt-get update

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs  | sh -s -- -y
RUN curl -L https://foundry.paradigm.xyz | bash

SHELL ["/bin/bash", "--login", "-i", "-c"]
RUN foundryup