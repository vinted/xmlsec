require 'mkmf'

if pkg_config('xmlsec1-openssl')
  create_makefile('xmlsec/xmlsec_ext')
else
  puts "xmlsec1 is not installed."
end