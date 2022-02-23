# README

Use following commands to create PKI

* intermediate cert

```shell
openssl genrsa -out intermediate.priv
openssl req -new -key intermediate.priv -out csr -nodes
openssl x509 -req -in csr -CA root.crt -CAkey root.priv -out intermediate.crt -days 365 -extfile intermediate.ext
rm csr
```

* EK cert (create 2 versions: v3 and v1)

```shell
openssl req -new -key ek.priv -out csr -nodes
openssl x509 -req -in csr -CAcreateserial -CA intermediate.crt -CAkey intermediate.priv -out ek_v3.crt -days 365 -extfile ek_v3.ext
openssl x509 -req -in csr -CAcreateserial -CA intermediate.crt -CAkey intermediate.priv -out ek.crt -days 365
rm csr
```
