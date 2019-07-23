require "spec_helper"

describe Signer do
  it "should digest and sign SOAP XML with security node and digested binary token" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_1.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")

    signer.document.xpath("//u:Timestamp", { "u" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }).each do |node|
      signer.digest!(node)
    end

    signer.document.xpath("//a:To", { "a" => "http://www.w3.org/2005/08/addressing" }).each do |node|
      signer.digest!(node)
    end

    signer.digest!(signer.binary_security_token_node)

    signer.sign!

    # File.open(File.join(File.dirname(__FILE__), 'fixtures', 'output_1.xml'), "w") do |f|
    #   f.write signer.document.to_s
    # end
    output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', 'output_1.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
  end

  it "should correctly canonicalize digested nodes (shouldn't account comments)" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_3_c14n_comments.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")

    signer.digest!(signer.document.at_xpath('//soap:Body', { 'soap' => 'http://www.w3.org/2003/05/soap-envelope'}))
    signer.sign!

    output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', 'output_3_c14n_comments.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
  end

  it "should digest and sign SOAP XML with SHA256" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_1.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
    signer.digest_algorithm = :sha256
    signer.signature_digest_algorithm = :sha256
    signer.signature_algorithm_id = 'http://www.w3.org/2001/04/xmlenc#sha256'

    signer.digest!(signer.binary_security_token_node)

    signer.sign!

    output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', 'output_1_sha256.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
  end

  it "should digest and sign SOAP XML with inclusive namespaces" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_1.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")

    signer.document.xpath("//soap:Body", { "soap" => "http://www.w3.org/2003/05/soap-envelope" }).each do |node|
      signer.digest!(node, inclusive_namespaces: ['s'])
    end

    signer.sign!(security_token: true, inclusive_namespaces: ['s'])

    output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', 'output_1_inclusive_namespaces.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
  end

  [
    [{ enveloped: true, enveloped_legacy: true }, 'output_2_legacy.xml'],
    [{ enveloped: true, enveloped_legacy: false }, 'output_2.xml'],
    [{ enveloped: true }, 'output_2.xml']
  ].each do |options, output_xml|
    it "should sign simple XML with options=#{options}" do
      input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_2.xml')
      cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
      private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

      signer = Signer.new(File.read(input_xml_file))
      signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
      signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
      signer.security_node = signer.document.root
      signer.security_token_id = ""
      signer.digest!(signer.document.root, id: "", **options)
      signer.sign!(:issuer_serial => true)

      # File.open(File.join(File.dirname(__FILE__), 'fixtures', 'output_2.xml'), "w") do |f|
      #   f.write signer.document.to_s
      # end
      output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', output_xml)

      signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
    end
  end


  it "should digest and sign SOAP XML with security node and digested binary token" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_4_with_nested_signatures.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
    signer.security_node = signer.document.at_xpath('//soap:Header/wsse:Security', soap: 'http://www.w3.org/2003/05/soap-envelope', wsse: Signer::WSSE_NAMESPACE)

    signer.document.xpath("//u:Timestamp", { "u" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }).each do |node|
      signer.digest!(node)
    end

    signer.document.xpath("//a:To", { "a" => "http://www.w3.org/2005/08/addressing" }).each do |node|
      signer.digest!(node)
    end

    signer.digest!(signer.binary_security_token_node)

    signer.sign!

    # File.open(File.join(File.dirname(__FILE__), 'fixtures', 'output_4_with_nested_signatures.xml'), "w") do |f|
    #   f.write signer.document.to_s
    # end
    output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', 'output_4_with_nested_signatures.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
  end

  [
    [{ enveloped: true, enveloped_legacy: true }, 'output_2_with_ds_prefix_legacy.xml'],
    [{ enveloped: true, enveloped_legacy: false }, 'output_2_with_ds_prefix.xml'],
    [{ enveloped: true }, 'output_2_with_ds_prefix.xml']
  ].each do |options, output_xml|
    it "should sign simple XML with custom DS namespace prefix with options=#{options}" do
      input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_2.xml')
      cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
      private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

      signer = Signer.new(File.read(input_xml_file))
      signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
      signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
      signer.security_node = signer.document.root
      signer.security_token_id = ""
      signer.ds_namespace_prefix = 'ds'

      signer.digest!(signer.document.root, id: "", **options)
      signer.sign!(issuer_serial: true)

      # File.open(File.join(File.dirname(__FILE__), 'fixtures', 'output_2_with_ds_prefix.xml'), "w") do |f|
      #   f.write signer.document.to_s
      # end
      output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', output_xml)

      signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
    end
  end

  it "should digest simple XML without transforms node" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_2.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
    signer.security_node = signer.document.root
    signer.security_token_id = ""
    signer.ds_namespace_prefix = 'ds'

    signer.digest!(signer.document.root, id: "", no_transform: true)
    signer.sign!(issuer_serial: true)

    expect(signer.document.at_xpath('//ds:Transforms', ds: Signer::DS_NAMESPACE)).to be_nil
  end

  [
    [{ enveloped: true, enveloped_legacy: true }, 'output_2_with_ds_prefix_and_wss_disabled_legacy.xml'],
    [{ enveloped: true, enveloped_legacy: false }, 'output_2_with_ds_prefix_and_wss_disabled.xml'],
    [{ enveloped: true }, 'output_2_with_ds_prefix_and_wss_disabled.xml']
  ].each do |options, output_xml|
    it "should partially sign element and simple XML with custom DS namespace prefix when wss is false with options=#{options}" do
      input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_2.xml')
      cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
      private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

      signer = Signer.new(File.read(input_xml_file), wss: false)
      signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
      signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
      signer.security_node = signer.document.root
      signer.security_token_id = ""
      signer.ds_namespace_prefix = 'ds'

      # partially sign element
      signer.digest!(signer.document.root.children.first, **options)

      signer.digest!(signer.document.root, id: "", **options)
      signer.sign!(issuer_serial: true)

      # File.open(File.join(File.dirname(__FILE__), 'fixtures', 'output_2_with_ds_prefix_and_wss_disabled.xml'), "w") do |f|
      #   f.write signer.document.to_s
      # end
      output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', output_xml)

      signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(:save_with => 0)
    end
  end

  it "should digest and sign SOAP XML with security node and digested binary token with noblanks disabled" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_4_with_nested_signatures.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file), noblanks: false)
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
    signer.security_node = signer.document.at_xpath('//soap:Header/wsse:Security', soap: 'http://www.w3.org/2003/05/soap-envelope', wsse: Signer::WSSE_NAMESPACE)

    signer.document.xpath("//u:Timestamp", { "u" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" }).each do |node|
      signer.digest!(node)
    end

    signer.document.xpath("//a:To", { "a" => "http://www.w3.org/2005/08/addressing" }).each do |node|
      signer.digest!(node)
    end

    signer.digest!(signer.binary_security_token_node)

    signer.sign!

    output_xml_file = File.join(File.dirname(__FILE__),
                                'fixtures',
                                'output_4_with_nested_signatures_with_noblanks_disabled.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file)).to_xml(save_with: 0)
  end

  it "should digest and sign SOAP XML with X509Data inside SecurityTokenReference node" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_5.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")

    # digest Body element from XML
    signer.digest!(signer.document.at_xpath('//soapenv:Body'), id: 'Body', inclusive_namespaces: ['soapenv'])

    # sign data from this request
    signer.sign!(issuer_serial: true, issuer_in_security_token: true)

    output_xml_file = File.join(File.dirname(__FILE__),
                                'fixtures',
                                'output_5_with_security_token.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
  end

  it "should digest and sign SOAP XML with X509Data" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_5.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")

    # digest Body element from XML
    signer.digest!(signer.document.at_xpath('//soapenv:Body'), id: 'Body', inclusive_namespaces: ['soapenv'])

    # sign data from this request
    signer.sign!(issuer_serial: true)

    output_xml_file = File.join(File.dirname(__FILE__),
                                'fixtures',
                                'output_5_with_x509_data.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(save_with: 0)
  end
end
