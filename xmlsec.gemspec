# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "xmlsec/version"

Gem::Specification.new do |s|
  s.name        = "xmlsec"
  s.version     = XmlSec::VERSION
  s.authors     = ["Tomas Didziokas", "Justas Janauskas", "Edvinas Bartkus", "Laurynas Butkus"]
  s.email       = ["tomas.did@gmail.com", "jjanauskas@gmail.com", "edvinas.bartkus@gmail.com", "laurynas.butkus@gmail.com"]
  s.homepage    = "https://github.com/friendlyfashion/xmlsec"
  s.extensions  = ["ext/xmlsec/extconf.rb"]
  s.summary     = "Ruby bindings for xmlsec"
  s.description = 'Ruby bindings for xmlsec'

  # s.rubyforge_project = "xmlsec"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  # tests
  s.add_development_dependency 'rake-compiler', "~> 0.7.7"
  s.add_development_dependency 'rake', '0.8.7' # NB: 0.8.7 required by rake-compiler 0.7.9
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'nokogiri'

end

