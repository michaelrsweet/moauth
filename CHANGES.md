Changes in mOAuth
=================


Changes in v2.0.0
-----------------

- Authorization tokens now use JWT/JWS/JWKS (Issue #7)


Changes in v1.1
---------------

- Now support dynamic client registration (Issue #8)
- Now support PAM-based authentication backends (Issue #9)
- Now install libmoauth, the `<moauth.h>` header, and a man page for the
  library.
- Updated `moauthd` to look for "/etc/moauthd.conf" and
  "/usr/local/etc/moauthd.conf" as the default configuration file, and install
  a "moauthd.conf.default" file as a template (Issue #10)
