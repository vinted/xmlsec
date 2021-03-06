# encoding: UTF-8

require 'rspec'
require 'xmlsec'
require 'nokogiri'

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :should
  end
  config.mock_with :rspec do |c|
    c.syntax = :should
  end
end

