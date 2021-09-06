# Hints

Decode a certificate in Erlang:

```
public_key:pem_entry_decode(hd(public_key:pem_decode(element(2, file:read_file("cert.pem"))))).
```

Decode a certificate with OpenSSL:

```
openssl x509 -in cert.pem -text
```
