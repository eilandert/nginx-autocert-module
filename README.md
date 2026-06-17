# nginx-autocert-module

NGINX dynamic module: automatic ACME certificate provisioning.

Goal: per-vhost or global `autocert on [email];` directive. Fetches certs
from an ACME CA (Lets Encrypt) only for the `server_name`s declared in the
vhost. Issues highest-strength keys (ECDSA, no RSA).
