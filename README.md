# Signer

[![Continuous Integration status](https://api.travis-ci.org/ebeigarts/signer.svg)](http://travis-ci.org/ebeigarts/signer)
[![Gem Version](https://badge.fury.io/rb/signer.svg)](http://badge.fury.io/rb/signer)

WS Security XML Certificate signing for Ruby

## Installation

```bash
gem install signer
```

## Usage

```ruby
require "signer"

signer = Signer.new(File.read("example.xml"))
signer.cert = OpenSSL::X509::Certificate.new(File.read("cert.pem"))
signer.private_key = OpenSSL::PKey::RSA.new(File.read("key.pem"), "password")

signer.document.xpath("//u:Timestamp", { "u" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }).each do |node|
  signer.digest!(node)
end

signer.document.xpath("//a:To", { "a" => "http://www.w3.org/2005/08/addressing" }).each do |node|
  signer.digest!(node)
end

signer.sign!(:security_token => true)

signer.to_xml
```

## Usage with Savon

```ruby
client = Savon::Client.new do |wsdl, http|
  wsdl.document = "..."
  wsdl.endpoint = "..."
end

response = client.request(:search_documents) do
  soap.version = 2
  soap.xml do
    builder = Nokogiri::XML::Builder.new do |xml|
      xml.send("s:Envelope",
        "xmlns:s" => "http://www.w3.org/2003/05/soap-envelope",
        "xmlns:a" => "http://www.w3.org/2005/08/addressing",
        "xmlns:u" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
      ) do
        xml.send("s:Header") do
          xml.send("a:Action", "s:mustUnderstand" => "1") do
            xml.text "http://tempuri.org/IDocumentService/SearchDocuments"
          end
          xml.send("a:MessageID") do
            xml.text "urn:uuid:30db5d4f-ab84-46be-907c-be690a92979b"
          end
          xml.send("a:ReplyTo") do
            xml.send("a:Address") do
              xml.text "http://www.w3.org/2005/08/addressing/anonymous"
            end
          end
          xml.send("a:To", "a:mustUnderstand" => "1") do
            xml.text "..."
          end
          xml.send("o:Security",
            "xmlns:o" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            "s:mustUnderstand" => "1"
          ) do
            xml.send("u:Timestamp") do
              time = Time.now.utc
              xml.send("u:Created") do
                xml.text(time.xmlschema)
              end
              xml.send("u:Expires") do
                xml.text((time + 5.minutes).xmlschema)
              end
            end
          end
        end
        xml.send("s:Body") do
          xml.send("SearchDocuments", "xmlns" => "http://tempuri.org/") do
            xml.send("searchCriteria",
              "xmlns:b" => "http://schemas.datacontract.org/2004/07/ZMDVS.BusinessLogic.Data.Documents.Integration",
              "xmlns:i" => "http://www.w3.org/2001/XMLSchema-instance"
            ) do
              xml.send("b:RegistrationNo") do
                xml.text "1"
              end
            end
          end
        end
      end
    end

    signer = Signer.new(builder.to_xml)
    signer.cert = OpenSSL::X509::Certificate.new(File.read("cert.pem"))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read("key.pem"), "test")

    signer.document.xpath("//u:Timestamp", { "u" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }).each do |node|
      signer.digest!(node)
    end

    signer.document.xpath("//a:To", { "a" => "http://www.w3.org/2005/08/addressing" }).each do |node|
      signer.digest!(node)
    end

    signer.sign!

    signer.to_xml
  end
end
```

## Example

Input:

```xml
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://tempuri.org/IDocumentService/SearchDocuments</a:Action>
    <a:MessageID>urn:uuid:30db5d4f-ab84-46be-907c-be690a92979b</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <To xmlns="http://www.w3.org/2005/08/addressing" xmlns:a="http://www.w3.org/2003/05/soap-envelope" a:mustUnderstand="1">http://tempuri.org/PublicServices/Test/1.0.12/PublicServices/DocumentService.svc</To>
    <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
      <u:Timestamp>
        <u:Created>2012-05-02T18:17:14.467Z</u:Created>
        <u:Expires>2012-05-02T18:22:14.467Z</u:Expires>
      </u:Timestamp>
    </o:Security>
  </s:Header>
  <s:Body>
    <SearchDocuments xmlns="http://tempuri.org/">
      <searchCriteria xmlns:b="http://schemas.datacontract.org/2004/07/BusinessLogic.Data.Documents.Integration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <b:RegistrationNo>1</b:RegistrationNo>
      </searchCriteria>
    </SearchDocuments>
  </s:Body>
</s:Envelope>
```

Output:

```xml
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://tempuri.org/IDocumentService/SearchDocuments</a:Action>
    <a:MessageID>urn:uuid:30db5d4f-ab84-46be-907c-be690a92979b</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <To xmlns="http://www.w3.org/2005/08/addressing" xmlns:a="http://www.w3.org/2003/05/soap-envelope" a:mustUnderstand="1" u:Id="_7e75a8ded22253b163ca76a40b6cc0c670ed0c33">http://tempuri.org/PublicServices/Test/1.0.12/PublicServices/DocumentService.svc</To>
    <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
      <u:Timestamp u:Id="_23dd13bb673d95ac7c29f0bebcca8268d39675b1">
        <u:Created>2012-05-02T18:17:14.467Z</u:Created>
        <u:Expires>2012-05-02T18:22:14.467Z</u:Expires>
      </u:Timestamp>
      <o:BinarySecurityToken u:Id="uuid-639b8970-7644-4f9e-9bc4-9c2e367808fc-1" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">MIICsDCCAhmgAwIBAgIJAOUHvh4oho0tMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTIwNTAzMTMxODIyWhcNMTMwNTAzMTMxODIyWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvK5hMPv/R5IFmwWyJOyEaFUrF/ZsmN+Gip8hvR6rLP3YPNx9iFYvPcZllFmuVwyaz7YT2N5BsqTwLdyi5v4HY4fUtuz0p8jIPoSd6dfDvcnSpf4QLTOgOaL3ciPEbgDHH2tnIksukoWzqCYva+qFZ74NFl19swXotW9fA4Jzs4QIDAQABo4GnMIGkMB0GA1UdDgQWBBRU1WEHDnP8Hr7ZulxrSzEwOcYpMzB1BgNVHSMEbjBsgBRU1WEHDnP8Hr7ZulxrSzEwOcYpM6FJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAOUHvh4oho0tMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEASY/9SAOK57q9mGnNJJeyDbmyGrAHSJTod646xTHYkMvhUqwHyk9PTr5bdfmswpmyVn+AQ43U2tU5vnpTBmKpHWD2+HSHgGa92mMLrfBOd8EBZ329NL3N2HDPIaHr4NPGyhNrSK3QVOnAq2D0jlyrGYJlLli1NxHiBz7FCEJaVI8=</o:BinarySecurityToken>
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
          <Reference URI="#_23dd13bb673d95ac7c29f0bebcca8268d39675b1">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <DigestValue>Oz29YgZk14+nchoqv9zGzhJcDUo=</DigestValue>
          </Reference>
          <Reference URI="#_7e75a8ded22253b163ca76a40b6cc0c670ed0c33">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <DigestValue>leV/RNYhwuCuD7/DBzn3IgQzUxI=</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue>en7YYAIn90ofH08aF917jNngMuse+vK6bihF0v6UsXFnGGMOflWfRTZ6mFmC2HwLmb2lSrhZ3eth3cs2fCBlEr/K2ZDMQfJo6CPxmbzfX/fxR/isCTDz+HIJd13J0HK4n+CzkndwplkCmT8SQlduUruUFUUmlQiiZQ7nryR+XyM=</SignatureValue>
        <KeyInfo>
          <o:SecurityTokenReference>
            <o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#uuid-639b8970-7644-4f9e-9bc4-9c2e367808fc-1"/>
          </o:SecurityTokenReference>
        </KeyInfo>
      </Signature>
    </o:Security>
  </s:Header>
  <s:Body>
    <SearchDocuments xmlns="http://tempuri.org/">
      <searchCriteria xmlns:b="http://schemas.datacontract.org/2004/07/BusinessLogic.Data.Documents.Integration" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <b:RegistrationNo>1</b:RegistrationNo>
      </searchCriteria>
    </SearchDocuments>
  </s:Body>
</s:Envelope>
```

## Different signature and digest algorithms support

You can change digest algorithms used for both node digesting and signing. Default for both is SHA1. Currently __SHA1__ `:sha1`, __SHA256__ `:sha256`, and __GOST R 34.11-94__ `:gostr3411` are supported out of the box.

```ruby
signer.digest_algorithm           = :sha256 # Set algorithm for node digesting
signer.signature_digest_algorithm = :sha256 # Set algorithm for message digesting for signing
```

You can provide you own digest support by passing in these methods a `Hash` with `:id` and `:digester` keys. In `:id` should be a string for XML `//Reference/DigestMethod[Algorithm]`, in `:digester` should be a Ruby object, compatible by interface with `OpenSSL::Digest` class, at least it should respond to `digest` and `reset` methods.

Signature algorithm is dependent from keypair used for signing and can't be changed. Usually it's __RSA__. Currently gem recognizes __GOST R 34.10-2001__ certificates and sets up a XML identifier for it. If used signature algorithm and signature digest doesn't corresponds with XML identifier, you can change identifier with `signature_algorithm_id` method.

Please note, that these settings will be changed or reset on certificate assignment, please change them after setting certificate!

__NOTE__: To sign XMLs with __GOST R 34.10-2001__, you need to have Ruby compiled with patches from https://bugs.ruby-lang.org/issues/9830 and correctly configured OpenSSL (see https://github.com/openssl/openssl/blob/master/engines/ccgost/README.gost)

## Miscellaneous

If you need to digest a `BinarySecurityToken` tag, you need to construct it yourself **before** signing.

```ruby
signer.digest!(signer.binary_security_token_node) # Constructing tag and digesting it
signer.sign! # No need to pass a :security_token option, as we already constructed and inserted this node
```

If you need to use canonicalization with inclusive namespaces you can pass array of namespace prefixes in `:inclusive_namespaces` option in both `digest!` and `sign!` methods.

If you need `Signature` tags to be in explicit namespace (say, `<ds:Signature>`) instead of to be in implicit default namespace you can specify next option:

```ruby
signer.ds_namespace_prefix = 'ds'
```

Every new instance of signer has Nokogiri `noblanks` set as default in process of parsing xml file. If you need to disable it, pass opional argument `noblanks: false`.

```ruby
Signer.new(File.read("example.xml"), noblanks: false)
```
