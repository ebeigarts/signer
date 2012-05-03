# -*- encoding: utf-8 -*-
require File.expand_path('../lib/signer/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Edgars Beigarts"]
  gem.email         = ["edgars.beigarts@gmail.com"]
  gem.description   = %q{WS Security XML signer}
  gem.summary       = gem.description
  gem.homepage      = ""

  gem.files         = Dir.glob("lib/**/*") + %w(README.md LICENSE)
  gem.test_files    = Dir.glob("spec/**/*")
  gem.executables   = []

  gem.name          = "signer"
  gem.require_paths = ["lib"]
  gem.version       = Signer::VERSION

  gem.add_development_dependency "rake"
  gem.add_development_dependency "rspec"

  gem.add_runtime_dependency "nokogiri", ">= 1.5.1"
end
