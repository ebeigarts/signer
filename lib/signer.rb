require "nokogiri"
require "base64"
require "digest/sha1"
require "openssl"

require "signer/version"

class Signer
  attr_accessor :document, :cert, :private_key
  attr_writer :security_node, :security_token_id

  def initialize(document)
    self.document = Nokogiri::XML(document.to_s, &:noblanks)
  end

  def to_xml
    document.to_xml(:save_with => 0)
  end

  def security_token_id
    @security_token_id ||= "uuid-639b8970-7644-4f9e-9bc4-9c2e367808fc-1"
  end

  def security_node
    @security_node ||= document.xpath("//o:Security", "o" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd").first
  end

  def canonicalize(node = document)
    node.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
  end

  # <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  def signature_node
    node = document.xpath("//ds:Signature", "ds" => "http://www.w3.org/2000/09/xmldsig#").first
    unless node
      node = Nokogiri::XML::Node.new('Signature', document)
      node.default_namespace = 'http://www.w3.org/2000/09/xmldsig#'
      security_node.add_child(node)
    end
    node
  end

  # <SignedInfo>
  #   <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  #   <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  #   ...
  # </SignedInfo>
  def signed_info_node
    node = signature_node.xpath("//ds:SignedInfo", "ds" => 'http://www.w3.org/2000/09/xmldsig#').first
    unless node
      node = Nokogiri::XML::Node.new('SignedInfo', document)
      signature_node.add_child(node)
      canonicalization_method_node = Nokogiri::XML::Node.new('CanonicalizationMethod', document)
      canonicalization_method_node['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
      node.add_child(canonicalization_method_node)
      signature_method_node = Nokogiri::XML::Node.new('SignatureMethod', document)
      signature_method_node['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
      node.add_child(signature_method_node)
    end
    node
  end

  # <o:BinarySecurityToken u:Id="" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
  #   ...
  # </o:BinarySecurityToken>
  # <SignedInfo>
  #   ...
  # </SignedInfo>
  # <KeyInfo>
  #   <o:SecurityTokenReference>
  #     <o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#uuid-639b8970-7644-4f9e-9bc4-9c2e367808fc-1"/>
  #   </o:SecurityTokenReference>
  # </KeyInfo>
  def binary_security_token_node
    node = document.xpath("//o:BinarySecurityToken", "o" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd").first
    unless node
      node = Nokogiri::XML::Node.new('BinarySecurityToken', document)
      node['u:Id']         = security_token_id
      node['ValueType']    = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
      node['EncodingType'] = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
      node.content = Base64.encode64(cert.to_der).gsub("\n", '')
      signature_node.add_previous_sibling(node)
      key_info_node = Nokogiri::XML::Node.new('KeyInfo', document)
      security_token_reference_node = Nokogiri::XML::Node.new('o:SecurityTokenReference', document)
      key_info_node.add_child(security_token_reference_node)
      reference_node = Nokogiri::XML::Node.new('o:Reference', document)
      reference_node['ValueType'] = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
      reference_node['URI'] = "##{security_token_id}"
      security_token_reference_node.add_child(reference_node)
      signed_info_node.add_next_sibling(key_info_node)
    end
    node
  end

  # <KeyInfo>
  #   <X509Data>
  #     <X509IssuerSerial>
  #       <X509IssuerName>System.Security.Cryptography.X509Certificates.X500DistinguishedName</X509IssuerName>
  #       <X509SerialNumber>13070789</X509SerialNumber>
  #     </X509IssuerSerial>
  #     <X509Certificate>MIID+jCCAuKgAwIBAgIEAMdxxTANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJTRTEeMBwGA1UEChMVTm9yZGVhIEJhbmsgQUIgKHB1YmwpMScwJQYDVQQDEx5Ob3JkZWEgcm9sZS1jZXJ0aWZpY2F0ZXMgQ0EgMDExFDASBgNVBAUTCzUxNjQwNi0wMTIwMB4XDTA5MDYxMTEyNTAxOVoXDTExMDYxMTEyNTAxOVowcjELMAkGA1UEBhMCU0UxIDAeBgNVBAMMF05vcmRlYSBEZW1vIENlcnRpZmljYXRlMRQwEgYDVQQEDAtDZXJ0aWZpY2F0ZTEUMBIGA1UEKgwLTm9yZGVhIERlbW8xFTATBgNVBAUTDDAwOTU1NzI0Mzc3MjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwcgz5AzbxTbsCE51No7fPnSqmQBIMW9OiPkiHotwYQTl+H9qwDvQRyBqHN26tnw7hNvEShd1ZRGUg4drMEXDV5CmKqsAevs9lauWDaHnGKPNHZJ1hNNYXHwymksEz5zMnG8eqRdhb4vOV2FzreJeYpsgx31Bv0aTofHcHVz4uGcCAwEAAaOCASAwggEcMAkGA1UdEwQCMAAwEQYDVR0OBAoECEj6Y9/vU03WMBMGA1UdIAQMMAowCAYGKoVwRwEDMBMGA1UdIwQMMAqACEIFjfLBeTpRMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYbaHR0cDovL29jc3Aubm9yZGVhLnNlL1JDQTAxMA4GA1UdDwEB/wQEAwIGQDCBiAYDVR0fBIGAMH4wfKB6oHiGdmxkYXA6Ly9sZGFwLm5iLnNlL2NuPU5vcmRlYSUyMHJvbGUtY2VydGlmaWNhdGVzJTIwQ0ElMjAwMSxvPU5vcmRlYSUyMEJhbmslMjBBQiUyMChwdWJsKSxjPVNFP2NlcnRpZmljYXRlcmV2b2NhdGlvbmxpc3QwDQYJKoZIhvcNAQEFBQADggEBAEXUv87VpHk51y3TqkMb1MYDqeKvQRE1cNcvhEJhIzdDpXMA9fG0KqvSTT1e0ZI2r78mXDvtTZnpic44jX2XMSmKO6n+1taAXq940tJUhF4arYMUxwDKOso0Doanogug496gipqMlpLgvIhGt06sWjNrvHzp2eGydUFdCsLr2ULqbDcut7g6eMcmrsnrOntjEU/J3hO8gyCeldJ+fI81qarrK/I0MZLR5LWCyVG/SKduoxHLX7JohsbIGyK1qAh9fi8l6X1Rcu80v5inpu71E/DnjbkAZBo7vsj78zzdk7KNliBIqBcIszdJ3dEHRWSI7FspRxyiR0NDm4lpyLwFtfw=</X509Certificate>
  #   </X509Data>
  # </KeyInfo>
  def x509_data_node
    issuer_name_node   = Nokogiri::XML::Node.new('X509IssuerName', document)
    issuer_name_node.content = "System.Security.Cryptography.X509Certificates.X500DistinguishedName"

    issuer_number_node = Nokogiri::XML::Node.new('X509SerialNumber', document)
    issuer_number_node.content = cert.serial

    issuer_serial_node = Nokogiri::XML::Node.new('X509IssuerSerial', document)
    issuer_serial_node.add_child(issuer_name_node)
    issuer_serial_node.add_child(issuer_number_node)

    cetificate_node    = Nokogiri::XML::Node.new('X509Certificate', document)
    cetificate_node.content = Base64.encode64(cert.to_der).gsub("\n", '')

    data_node          = Nokogiri::XML::Node.new('X509Data', document)
    data_node.add_child(issuer_serial_node)
    data_node.add_child(cetificate_node)

    key_info_node      = Nokogiri::XML::Node.new('KeyInfo', document)
    key_info_node.add_child(data_node)

    signed_info_node.add_next_sibling(key_info_node)

    data_node
  end

  # <Reference URI="#_0">
  #   <Transforms>
  #     <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  #   </Transforms>
  #   <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
  #   <DigestValue>aeqXriJuUCk4tPNPAGDXGqHj6ao=</DigestValue>
  # </Reference>
  def digest!(target_node, options = {})
    id = options[:id] || "_#{Digest::SHA1.hexdigest(target_node.to_s)}"
    target_node['u:Id'] = id if id.size > 0
    target_canon = canonicalize(target_node)
    target_digest = Base64.encode64(OpenSSL::Digest::SHA1.digest(target_canon)).strip

    reference_node = Nokogiri::XML::Node.new('Reference', document)
    reference_node['URI'] = id.size > 0 ? "##{id}" : ""
    signed_info_node.add_child(reference_node)

    transforms_node = Nokogiri::XML::Node.new('Transforms', document)
    reference_node.add_child(transforms_node)

    transform_node = Nokogiri::XML::Node.new('Transform', document)
    if options[:enveloped]
      transform_node['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
    else
      transform_node['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    end
    transforms_node.add_child(transform_node)

    digest_method_node = Nokogiri::XML::Node.new('DigestMethod', document)
    digest_method_node['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#sha1'
    reference_node.add_child(digest_method_node)

    digest_value_node = Nokogiri::XML::Node.new('DigestValue', document)
    digest_value_node.content = target_digest
    reference_node.add_child(digest_value_node)
    self
  end

  # <SignatureValue>...</SignatureValue>
  def sign!(options = {})
    if options[:security_token]
      binary_security_token_node
    end

    if options[:issuer_serial]
      x509_data_node
    end

    signed_info_canon = canonicalize(signed_info_node)

    signature = private_key.sign(OpenSSL::Digest::SHA1.new, signed_info_canon)
    signature_value_digest = Base64.encode64(signature).gsub("\n", '')

    signature_value_node = Nokogiri::XML::Node.new('SignatureValue', document)
    signature_value_node.content = signature_value_digest
    signed_info_node.add_next_sibling(signature_value_node)
    self
  end
end
