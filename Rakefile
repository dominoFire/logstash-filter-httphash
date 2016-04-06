require "logstash/devutils/rake"

Gem::Specification.new do |s|
  s.name = 'logstash-filter-httphash'
  s.version = '0.1.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = "This filter does a hash over a file accesible via HTTP"
  s.description = "This filter does a hash over a file accesible via HTTP"
  s.authors = ["dominofire"]
  s.email = 'fer.aguilar.reyes@gmail.com'
  s.homepage = "http://github.com/dominofire/logstash-filter-httphash"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '>= 1.4.0', '< 2.0.0'
  s.add_development_dependency 'logstash-devutils'
end
