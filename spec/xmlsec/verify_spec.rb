require 'spec_helper'

describe XmlSec do

  it "should verify signed.test.xml with public key" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    XmlSec::valid_file?(
        File.join(asset_dir, 'signed.test.xml'),
        File.join(asset_dir, 'public.key.pem'),
        nil
      ).should be_true

  end

  it "should verify signed.test.xml certificate" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    XmlSec::valid_file?(
        File.join(asset_dir, 'signed.test.xml'),
        nil,
        File.join(asset_dir, 'x509.crt')
      ).should be_true

  end


  it "should verify xml string with public key" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    XmlSec::valid?(
        File.open(File.join(asset_dir, 'signed.test.xml'), 'rb') { |f| f.read },
        File.join(asset_dir, 'public.key.pem'),
        nil
      ).should be_true

  end

  it "should verify xml string certificate" do
    asset_dir = File.expand_path('../../assets', __FILE__)
    XmlSec::valid?(
        File.open(File.join(asset_dir, 'signed.test.xml'), 'rb') { |f| f.read },
        nil,
        File.join(asset_dir, 'x509.crt')
      ).should be_true

  end

end