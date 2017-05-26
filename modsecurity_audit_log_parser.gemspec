# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'modsecurity_audit_log_parser/version'

Gem::Specification.new do |spec|
  spec.name          = "modsecurity_audit_log_parser"
  spec.version       = ModsecurityAuditLogParser::VERSION
  spec.authors       = ["Hiroshi Nakamura"]
  spec.email         = ["nahi@ruby-lang.org"]

  spec.summary       = %q{Modsecurity AuditLog parser library.}
  spec.description   = %q{For parsing AuditLog.}
  spec.homepage      = "https://github.com/nahi/modsecurity_audit_log_parser"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
