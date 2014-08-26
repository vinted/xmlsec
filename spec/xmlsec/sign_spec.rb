require 'spec_helper'

describe XmlSec do
  it "should sign unsigned.test.xml with unprotected private key" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.key.pem'),
        nil,
        nil,
        nil
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign unsigned.test.xml with protected private key" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        nil,
        nil
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign unsigned.test.xml with protected private key and add certificate" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        File.join(asset_dir, 'x509.crt'),
        nil
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign unsigned.test.xml with unprotected private key and add certificate" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.key.pem'),
        nil,
        File.join(asset_dir, 'x509.crt'),
        nil
      )
    doc = Nokogiri::XML(xml)

    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)
  end

  it "should sign unsigned.test.xml with unprotected private key, signature must be placed in <Security> tag" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.key.pem'),
        nil,
        nil,
        'Security'
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign unsigned.test.xml with protected private key, signature must be placed in <Security> tag" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        nil,
        'Security'
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign unsigned.test.xml with protected private key and add certificat, signature must be placed in <Security> tage" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        File.join(asset_dir, 'x509.crt'),
        'Security'
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign unsigned.test.xml with unprotected private key and add certificate, signature must be placed in <Security> tag" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign_file(
        File.join(asset_dir, 'unsigned.test.xml'),
        File.join(asset_dir, 'private.key.pem'),
        nil,
        File.join(asset_dir, 'x509.crt'),
        'Security'
      )
    doc = Nokogiri::XML(xml)
    File.open(File.join(asset_dir, 'signed.test.xml'), "w") {|f| f.puts xml }


    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)
  end

  it "should sign xml string with unprotected private key" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.key.pem'),
        nil,
        nil,
        nil
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign xml string with protected private key" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        nil,
        nil
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign xml string with protected private key and add certificate" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        File.join(asset_dir, 'x509.crt'),
        nil
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign xml string with unprotected private key and add certificate" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.key.pem'),
        nil,
        File.join(asset_dir, 'x509.crt'),
        nil
      )
    doc = Nokogiri::XML(xml)

    doc.xpath(
        "Service/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)
  end

  it "should sign xml string with unprotected private key, signature must be placed in <Security> tag" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.key.pem'),
        nil,
        nil,
        'Security'
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign xml string with protected private key, signature must be placed in <Security> tag" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        nil,
        'Security'
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign xml string with protected private key and add certificat, signature must be placed in <Security> tage" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.passw.key.pem'),
        'testas',
        File.join(asset_dir, 'x509.crt'),
        'Security'
      )
    doc = Nokogiri::XML(xml)
    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

  end

  it "should sign xml string with unprotected private key and add certificate, signature must be placed in <Security> tag" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    xml = XmlSec::sign(
        '<?xml version="1.0" encoding="UTF-8"?><Service><Data>Hello</Data></Service>',
        File.join(asset_dir, 'private.key.pem'),
        nil,
        File.join(asset_dir, 'x509.crt'),
        'Security'
      )
    doc = Nokogiri::XML(xml)

    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:SignatureValue",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)

    doc.xpath(
        "Service/Security/xmlns:Signature/xmlns:KeyInfo/xmlns:X509Data/xmlns:X509Certificate",
        "xmlns" => "http://www.w3.org/2000/09/xmldsig#"
      ).count.should eql(1)
  end
end
