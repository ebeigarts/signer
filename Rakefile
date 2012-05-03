#!/usr/bin/env rake
require "bundler/gem_tasks"

require "rspec/core/rake_task"

Bundler::GemHelper.install_tasks
RSpec::Core::RakeTask.new(:spec)
task :default => :spec

task :generate_cert_and_private_key do
  system "openssl req -new -x509 -keyout spec/fixtures/key.pem -out spec/fixtures/cert.pem -days 365"
end
  