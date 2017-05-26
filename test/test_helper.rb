$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'modsecurity_audit_log_parser'

require 'minitest/autorun'

module PartTestHelper
  def add(part, content)
    content.each_line do |line|
      part.add(line)
    end
    part
  end
end
