FROM pwn.red/jail
COPY --from=ubuntu@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092 / /srv

COPY ./chall /srv/app/run
COPY ./flag.txt /srv/app/flag.txt

ENV JAIL_PORT=1337

