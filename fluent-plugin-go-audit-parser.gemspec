lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = "fluent-plugin-go-audit-parser"
  spec.version = "0.1.1"
  spec.authors = ["haccht"]
  spec.email   = ["haccht@users.noreply.github.com"]

  spec.summary       = %q{Fluentd plugin to transform go-audit log and make it easy to be handled by modern log aggregators.}
  spec.description   = %q{Fluentd plugin to transform go-audit log and make it easy to be handled by modern log aggregators.}
  spec.homepage      = "https://github.com/haccht/fluent-plugin-go-audit-parser"
  spec.license       = "Apache-2.0"

  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.files         = files
  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = test_files
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.2.20"
  spec.add_development_dependency "rake", "~> 13.0.6"
  spec.add_development_dependency "test-unit", "~> 3.4.4"
  spec.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]
end
