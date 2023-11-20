FROM ghcr.io/dev-bio/actions-base:latest

COPY ./target/release/action action

CMD ["/action"]
