require "spec_helper"

describe Signer do
  it "should digest and sign SOAP XML with security node and binary token" do
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

    signer.sign!(:security_token => true)

    # File.open(File.join(File.dirname(__FILE__), 'fixtures', 'output_1.xml'), "w") do |f|
    #   f.write signer.document.to_s
    # end
    output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', 'output_1.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(:save_with => 0)
  end

  it "should sign simple XML" do
    input_xml_file   = File.join(File.dirname(__FILE__), 'fixtures', 'input_2.xml')
    cert_file        = File.join(File.dirname(__FILE__), 'fixtures', 'cert.pem')
    private_key_file = File.join(File.dirname(__FILE__), 'fixtures', 'key.pem')

    signer = Signer.new(File.read(input_xml_file))
    signer.cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    signer.private_key = OpenSSL::PKey::RSA.new(File.read(private_key_file), "test")
    signer.security_node = signer.document.root
    signer.security_token_id = ""
    signer.digest!(signer.document, :id => "", :enveloped => true)
    signer.sign!(:issuer_serial => true)

    # File.open(File.join(File.dirname(__FILE__), 'fixtures', 'output_2.xml'), "w") do |f|
    #   f.write signer.document.to_s
    # end
    output_xml_file = File.join(File.dirname(__FILE__), 'fixtures', 'output_2.xml')

    signer.to_xml.should == Nokogiri::XML(File.read(output_xml_file), &:noblanks).to_xml(:save_with => 0)
  end
end
