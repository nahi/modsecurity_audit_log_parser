require 'modsecurity_audit_log_parser/version'
require 'date'

class ModsecurityAuditLogParser
  class Log
    attr_reader :id

    def initialize(id)
      @id = id
      @parts = {}
    end

    def add(part)
      @parts[part.type] = part
    end

    MODSEC_TIMESTAMP_FORMAT = '%d/%b/%Y:%H:%M:%S %z'
    def time
      if ts = audit_log_header&.timestamp
        DateTime.strptime(ts, MODSEC_TIMESTAMP_FORMAT).to_time.to_i rescue 0
      end
    end

    [:timestamp, :unique_transaction_id, :source_ip_address, :source_port, :destination_ip_address, :destination_port].each do |name|
      define_method(name) do
        audit_log_header&.send(name)
      end
    end

    def trailers
      audit_log_trailer&.trailers
    end

    def rules
      audit_log_trailer&.rules
    end

    def audit_log_header
      @parts['A']
    end

    def request_headers
      @parts['B']
    end

    def request_body
      @parts['C']
    end

    def original_response_body
      @parts['E']
    end

    def response_header
      @parts['F']
    end

    def audit_log_trailer
      @parts['H']
    end

    def reduced_multipart_request_body
      @parts['I']
    end

    def multipart_files_information
      @parts['J']
    end

    def matched_rules_information
      @parts['K']
    end

    def to_h
      @parts.inject(Hash.new) { |r, (k, v)|
        v.merge!(r)
        r
      }
    end
  end

  class Part
    module PartClassMethods
      def register(type, klass)
        (@@registry ||= {})[type] = klass
        @type = type
      end

      def type
        @type
      end
      
      def self.class_for_type(type)
        @@registry[type]
      end
    end

    def self.inherited(klass)
      klass.extend(PartClassMethods)
    end

    def type
      self.class.type
    end

    def self.new_subclass(type)
      PartClassMethods.class_for_type(type).new
    end

    def add(line)
      raise
    end

    def to_hash
      hash = {}
      merge!(hash)
      hash
    end

    def merge!(hash)
      raise
    end
  end

  class ContentPart < Part
    attr_reader :content

    def initialize
      @content = ''
    end

    def add(line)
      @content << line
    end
  end

  class AuditLogHeaderPart < Part
    register('A', self)

    attr_reader :timestamp, :unique_transaction_id, :source_ip_address, :source_port, :destination_ip_address, :destination_port

    def add(line)
      datetime, rest = line.chomp.split(/\] /, 2)
      @timestamp = datetime.sub(/\[/, '')
      @unique_transaction_id, @source_ip_address, @source_port, @destination_ip_address, @destination_port = rest.split(/ /, 5)
    end

    def merge!(hash)
      hash[:timestamp] = @timestamp
      hash[:unique_transaction_id] = @unique_transaction_id
      hash[:source_ip_address] = @source_ip_address
      hash[:source_port] = @source_port
      hash[:destination_ip_address] = @destination_ip_address
      hash[:destination_port] = @destination_port
    end
  end

  class RequestHeadersPart < ContentPart
    register('B', self)

    def merge!(hash)
      hash[:request_headers] = @content
    end
  end

  class RequestBodyPart < ContentPart
    register('C', self)

    def merge!(hash)
      hash[:request_body] = @content
    end
  end

  class OriginalResponseBodyPart < ContentPart
    register('E', self)

    def merge!(hash)
      hash[:original_response_body] = @content
    end
  end

  class ResponseHeadersPart < ContentPart
    register('F', self)

    def merge!(hash)
      hash[:response_headers] = @content
    end
  end

  class AuditLogTrailerPart < Part
    register('H', self)

    attr_reader :trailers

    def initialize
      @trailers = {}
    end

    def add(line)
      key, value = line.chomp.split(/: /, 2)
      if key == 'Message'
        (@trailers[:Message] ||= '') << value << "\n"
      elsif key
        @trailers[key.intern] = value
      end
    end

    def rules
      if pairs = @trailers[:Message]&.scan(/\[(\w+) "([^\\"]*(?:\\.[^\\"]*)*)"\]/)
        pairs.inject({}) { |r, (k, v)|
          r["rule_#{k}".intern] = v
          r
        }
      end
    end

    def merge!(hash)
      hash.merge!(@trailers)
      if h = rules
        hash.merge!(h)
      end
    end
  end

  class ReducedMultipartRequestBodyPart < ContentPart
    register('I', self)

    def merge!(hash)
      hash[:reduce_multipart_request_body] = @content
    end
  end

  class MultipartFilesInformationPart < ContentPart
    register('J', self)

    def merge!(hash)
      hash[:multipart_files_information] = @content
    end
  end

  class MatchedRulesInformationPart < ContentPart
    register('K', self)

    def merge!(hash)
      hash[:matched_rules_information] = @content
    end
  end

  class AuditLogFooterPart < Part
    register('Z', self)

    def add(line)
      # ignore
    end

    def merge!(hash)
      # ignore
    end
  end

  def initialize(targets = 'ABCEFHIJKZ')
    @targets = targets.split('')
    @records = []
  end

  def parse(str)
    str.each_line do |line|
      if /\A--([0-9a-z]+)-(.)--/ =~ line
        id, type = $1, $2
        if @log.nil? or @log.id != id
          @log = Log.new(id)
          @records << @log
        end
        unless @targets.include?(type)
          @part = nil
          next
        end
        @part = Part.new_subclass(type)
        @log.add(@part)
      else
        @part.add(line) if @part
      end
    end
    self
  end

  # Caller makes sure that all stream was passed to `parse`
  def shift(*a)
    @records.shift(*a)
  end
end


if $0 == __FILE__
  parser = ModsecurityAuditLogParser.new
  parser.parse(ARGF)
  parser.shift(100).each do |log|
    p log.to_h
  end
end
