## 1.5.0 (2017-01-23)

- Add posibility to disable noblanks method in Signer initialization (#16, @bpietraga)
- Minimum ruby version is now 2.1

## 1.4.3 (2015-10-28)

- Fixed Issuer Name node (#8, @tiagocasanovapt)

## 1.4.2 (2014-11-30)

- Fixed behaviour on XMLs that already contains nested signatures somewhere

## 1.4.1 (2014-09-09)

- Changed method of getting GOST R 34.11-94 digest algorithm to more short and generic (and working in Ubuntu 14.04 and other OS)

## 1.4.0 (2014-06-24)

- Support signing and digesting with inclusive namespaces (#5, @Envek)

## 1.3.1 (2014-06-24)

- Fix namespace issue for SecurityTokenReference tag (#4, #@Envek)

## 1.3.0 (2014-06-16)

- Allow to sign with other digest algorithms - SHA1, SHA256, and GOST R 34.11-94 (#3, @Envek)

## 1.2.1 (2014-05-14)

- Fix canonicalization: should be without comments (#2, @Envek)

## 1.2.0 (2014-05-06)

- Id and attribute namespace preserving when digesting the nodes (#1, @Envek)

## 1.1.1 (2013-04-03)

- Allow to sign using enveloped-signature

## 1.1.0 (2012-06-21)

- Allow to sign XML documents without SOAP

## 1.0.0 (2012-05-03)

- Allow to sign SOAP documents
