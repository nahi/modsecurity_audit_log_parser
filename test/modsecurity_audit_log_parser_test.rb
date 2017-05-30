require 'test_helper'

class AuditLogHeaderPartTest < Minitest::Test
  CONTENT = '[23/May/2017:07:44:10 +0000] mcAcAcecAcAcAbAcAcAcAcmo 123.45.67.8 60491 127.0.0.1 80'

  def test_add
    part = ModsecurityAuditLogParser::AuditLogHeaderPart.new
    part.add(CONTENT)
    assert_equal 'A', part.type
    assert_equal '23/May/2017:07:44:10 +0000', part.timestamp
    assert_equal 'mcAcAcecAcAcAbAcAcAcAcmo', part.unique_transaction_id
    assert_equal '123.45.67.8', part.source_ip_address
    assert_equal '60491', part.source_port
    assert_equal '127.0.0.1', part.destination_ip_address
    assert_equal '80', part.destination_port
  end

  def test_hash
    part = ModsecurityAuditLogParser::AuditLogHeaderPart.new
    part.add(CONTENT)
    assert_equal(
      {
        timestamp: "23/May/2017:07:44:10 +0000",
        unique_transaction_id: "mcAcAcecAcAcAbAcAcAcAcmo",
        source_ip_address: "123.45.67.8",
        source_port: "60491",
        destination_ip_address: "127.0.0.1",
        destination_port: "80"
      },
      {}.merge(part)
    )
  end
end

class RequestHeadersPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = <<__EOM__
GET /system/v1/status HTTP/1.1
host: 123.45.67.8:1234
User-Agent: ELB-HealthChecker/1.0
Accept: */*
Connection: keep-alive

__EOM__

  def test_add
    part = add(ModsecurityAuditLogParser::RequestHeadersPart.new, CONTENT)
    assert_equal 'B', part.type
    assert_equal CONTENT, part.content
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::RequestHeadersPart.new, CONTENT)
    assert_equal(
      {request_headers: CONTENT},
      {}.merge(part)
    )
  end
end

class RequestBodyPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = '{"nahi":"nahi"}'

  def test_add
    part = add(ModsecurityAuditLogParser::RequestBodyPart.new, CONTENT)
    assert_equal 'C', part.type
    assert_equal CONTENT, part.content
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::RequestBodyPart.new, CONTENT)
    assert_equal(
      {request_body: CONTENT},
      {}.merge(part)
    )
  end
end

class OriginalResponseBodyPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = '{"nahi":"nahi"}'

  def test_add
    part = add(ModsecurityAuditLogParser::OriginalResponseBodyPart.new, CONTENT)
    assert_equal 'E', part.type
    assert_equal CONTENT, part.content
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::OriginalResponseBodyPart.new, CONTENT)
    assert_equal(
      {original_response_body: CONTENT},
      {}.merge(part)
    )
  end
end

class ResponseHeadersPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = <<__EOM__
HTTP/1.1 400 Bad Request
Server: Nahi server
Content-Type: application/json
Content-Length: 2
Connection: keep-alive

__EOM__

  def test_add
    part = add(ModsecurityAuditLogParser::ResponseHeadersPart.new, CONTENT)
    assert_equal 'F', part.type
    assert_equal CONTENT, part.content
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::ResponseHeadersPart.new, CONTENT)
    assert_equal(
      {response_headers: CONTENT},
      {}.merge(part)
    )
  end
end

class AuditLogTrailerPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = <<__EOM__
Message: Warning. Match of "eq 0" against "REQBODY_ERROR" required. [file "/path/to/conf.d/modsecurity.conf"] [line "60"] [id "200002"] [msg "Failed to parse request body."] [data ""] [severity "CRITICAL"]
Message: Warning. Match of "eq 0" against "REQBODY_ERROR" required. [file "/path/to/conf.d/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "157"] [id "920130"] [rev "1"] [msg "Failed to parse request body."] [data ""] [severity "CRITICAL"] [ver "OWASP_CRS/3.0.0"] [maturity "9"] [accuracy "9"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS/PROTOCOL_VIOLATION/INVALID_REQ"] [tag "CAPEC-272"]
Apache-Handler: IIS
Stopwatch: 1495601080000788 792314 (- - -)
Stopwatch2: 1495601080000788 792314; combined=1704, p1=313, p2=1178, p3=68, p4=105, p5=40, sr=45, sw=0, l=0, gc=0
Response-Body-Transformed: Dechunked
Producer: ModSecurity for nginx (STABLE)/2.9.0 (http://www.modsecurity.org/); OWASP_CRS/3.0.2.
Server: ModSecurity Standalone
Engine-Mode: "DETECTION_ONLY"

__EOM__

  def test_add
    part = add(ModsecurityAuditLogParser::AuditLogTrailerPart.new, CONTENT)
    assert_equal 'H', part.type
    assert_equal(
      "Warning. Match of \"eq 0\" against \"REQBODY_ERROR\" required. [file \"/path/to/conf.d/modsecurity.conf\"] [line \"60\"] [id \"200002\"] [msg \"Failed to parse request body.\"] [data \"\"] [severity \"CRITICAL\"]
Warning. Match of \"eq 0\" against \"REQBODY_ERROR\" required. [file \"/path/to/conf.d/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf\"] [line \"157\"] [id \"920130\"] [rev \"1\"] [msg \"Failed to parse request body.\"] [data \"\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"9\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-protocol\"] [tag \"OWASP_CRS/PROTOCOL_VIOLATION/INVALID_REQ\"] [tag \"CAPEC-272\"]\n",
      part.trailers[:Message]
    )
    assert_equal "IIS", part.trailers[:'Apache-Handler']
    assert_equal "1495601080000788 792314 (- - -)", part.trailers[:'Stopwatch']
    assert_equal "1495601080000788 792314; combined=1704, p1=313, p2=1178, p3=68, p4=105, p5=40, sr=45, sw=0, l=0, gc=0", part.trailers[:'Stopwatch2']
    assert_equal "Dechunked", part.trailers[:'Response-Body-Transformed']
    assert_equal "ModSecurity for nginx (STABLE)/2.9.0 (http://www.modsecurity.org/); OWASP_CRS/3.0.2.", part.trailers[:'Producer']
    assert_equal "ModSecurity Standalone", part.trailers[:'Server']
    assert_equal "\"DETECTION_ONLY\"", part.trailers[:'Engine-Mode']
  end

  def test_rules
    part = add(ModsecurityAuditLogParser::AuditLogTrailerPart.new, CONTENT)
    assert_equal(
      {
        rule_file: "/path/to/conf.d/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
        rule_line: "157",
        rule_id: "920130",
        rule_msg: "Failed to parse request body.",
        rule_data: "",
        rule_severity: "CRITICAL",
        rule_rev: "1",
        rule_ver: "OWASP_CRS/3.0.0",
        rule_maturity: "9",
        rule_accuracy: "9",
        rule_tag: "CAPEC-272"
      },
      part.rules
    )
  end

  def test_hash
    part = ModsecurityAuditLogParser::AuditLogTrailerPart.new
    CONTENT.each_line do |line|
      part.add(line)
    end
    assert_equal 'OWASP_CRS/3.0.0', {}.merge(part)[:rule_ver]
  end
end

class ReducedMultipartRequestBodyPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = <<__EOM__
TODO: not captured yet

__EOM__

  def test_add
    part = add(ModsecurityAuditLogParser::ReducedMultipartRequestBodyPart.new, CONTENT)
    assert_equal 'I', part.type
    assert_equal CONTENT, part.content
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::ReducedMultipartRequestBodyPart.new, CONTENT)
    assert_equal(
      {reduce_multipart_request_body: CONTENT},
      {}.merge(part)
    )
  end
end

class MultipartFilesInformationPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = <<__EOM__
TODO: not captured yet

__EOM__

  def test_add
    part = add(ModsecurityAuditLogParser::MultipartFilesInformationPart.new, CONTENT)
    assert_equal 'J', part.type
    assert_equal CONTENT, part.content
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::MultipartFilesInformationPart.new, CONTENT)
    assert_equal(
      {multipart_files_information: CONTENT},
      {}.merge(part)
    )
  end
end

class MatchedRulesInformationPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = <<__EOM__
TODO: not captured yet

__EOM__

  def test_add
    part = add(ModsecurityAuditLogParser::MatchedRulesInformationPart.new, CONTENT)
    assert_equal 'K', part.type
    assert_equal CONTENT, part.content
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::MatchedRulesInformationPart.new, CONTENT)
    assert_equal(
      {matched_rules_information: CONTENT},
      {}.merge(part)
    )
  end
end

class AuditLogFooterPartTest < Minitest::Test
  include PartTestHelper

  CONTENT = <<__EOM__

__EOM__

  def test_add
    part = add(ModsecurityAuditLogParser::AuditLogFooterPart.new, CONTENT)
    assert_equal 'Z', part.type
  end

  def test_hash
    part = add(ModsecurityAuditLogParser::AuditLogFooterPart.new, CONTENT)
    assert_equal({}, {}.merge(part))
  end
end

class ModsecurityAuditLogParserTest < Minitest::Test
  CONTENT = <<__EOM__
--2e793d5f-A--
[23/May/2017:07:44:10 +0000] mcAcAcecAcAcAbAcAcAcAcmo 123.45.67.8 60491 127.0.0.1 80
--2e793d5f-B--
HTTP/1.1 200 OK
Server: 
Content-Type: application/json
Content-Length: 15
Connection: keep-alive

--2e793d5f-F--
HTTP/1.1 400 Bad Request
Server: Nahi server
Content-Type: application/json
Content-Length: 2
Connection: keep-alive

--2e793d5f-E--

--2e793d5f-H--
Message: Warning. Match of "eq 0" against "REQBODY_ERROR" required. [file "/path/to/conf.d/modsecurity.conf"] [line "60"] [id "200002"] [msg "Failed to parse request body."] [data ""] [severity "CRITICAL"]
Message: Warning. Match of "eq 0" against "REQBODY_ERROR" required. [file "/path/to/conf.d/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "157"] [id "920130"] [rev "1"] [msg "Failed to parse request body."] [data ""] [severity "CRITICAL"] [ver "OWASP_CRS/3.0.0"] [maturity "9"] [accuracy "9"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-protocol"] [tag "OWASP_CRS/PROTOCOL_VIOLATION/INVALID_REQ"] [tag "CAPEC-272"]
Apache-Handler: IIS
Stopwatch: 1495601080000788 792314 (- - -)
Stopwatch2: 1495601080000788 792314; combined=1704, p1=313, p2=1178, p3=68, p4=105, p5=40, sr=45, sw=0, l=0, gc=0
Response-Body-Transformed: Dechunked
Producer: ModSecurity for nginx (STABLE)/2.9.0 (http://www.modsecurity.org/); OWASP_CRS/3.0.2.
Server: ModSecurity Standalone
Engine-Mode: "DETECTION_ONLY"

--2e793d5f-Z--

__EOM__

  def test_that_it_has_a_version_number
    refute_nil ::ModsecurityAuditLogParser::VERSION
  end

  def test_parse
    parser = parse(ModsecurityAuditLogParser.new, CONTENT)
    log = parser.shift
    assert_equal '23/May/2017:07:44:10 +0000', log.timestamp
    assert_equal 'mcAcAcecAcAcAbAcAcAcAcmo', log.unique_transaction_id
    assert_equal '123.45.67.8', log.source_ip_address
    assert_equal '60491', log.source_port
    assert_equal '127.0.0.1', log.destination_ip_address
    assert_equal '80', log.destination_port
    assert_equal '1495601080000788 792314 (- - -)', log.trailers[:Stopwatch]
    assert_equal 'Failed to parse request body.', log.rules[:rule_msg]
    assert_equal '23/May/2017:07:44:10 +0000', log.audit_log_header.timestamp
    assert_equal 'HTTP/1.1 200 OK', log.request_headers.content.split(/\n/).first
    assert_nil log.request_body
    assert_equal "\n", log.original_response_body.content
    assert_equal 'HTTP/1.1 400 Bad Request', log.response_header.content.split(/\n/).first
    assert_equal '1495601080000788 792314; combined=1704, p1=313, p2=1178, p3=68, p4=105, p5=40, sr=45, sw=0, l=0, gc=0', log.audit_log_trailer.trailers[:Stopwatch2]
    assert_nil log.reduced_multipart_request_body
    assert_nil log.multipart_files_information
    assert_nil log.matched_rules_information
    assert_equal 1495525450, log.time # 23/May/2017:07:44:10 +0000

    assert_nil parser.shift
  end

  def test_parse_broken_timestamp
    assert_equal 0, parse(ModsecurityAuditLogParser.new, <<__EOM__).shift.time # May 32 -> 0
--2e793d5f-A--
[32/May/2017:07:44:10 +0000] mcAcAcecAcAcAbAcAcAcAcmo 123.45.67.8 60491 127.0.0.1 80
--2e793d5f-Z--

__EOM__
  end

  def test_parse_each_line
    parser = ModsecurityAuditLogParser.new
    CONTENT.each_line do |line|
      parser.parse(line)
    end
    log = parser.shift
    assert_equal 'Failed to parse request body.', log.rules[:rule_msg]
    assert_nil parser.shift
  end

  def test_parse_skip
    log = parse(ModsecurityAuditLogParser.new('AH'), CONTENT).shift
    assert_equal '23/May/2017:07:44:10 +0000', log.timestamp
    assert_equal '23/May/2017:07:44:10 +0000', log.audit_log_header.timestamp
    assert_nil log.request_headers
    assert_nil log.request_body
    assert_nil log.original_response_body
    assert_nil log.response_header
    assert_equal '1495601080000788 792314; combined=1704, p1=313, p2=1178, p3=68, p4=105, p5=40, sr=45, sw=0, l=0, gc=0', log.audit_log_trailer.trailers[:Stopwatch2]
    assert_nil log.reduced_multipart_request_body
    assert_nil log.multipart_files_information
    assert_nil log.matched_rules_information
  end

  def test_shift_returns_log_after_footer
    assert_nil parse(ModsecurityAuditLogParser.new('AH'), <<__EOM__).shift
--2e793d5f-A--
[23/May/2017:07:44:10 +0000] mcAcAcecAcAcAbAcAcAcAcmo 123.45.67.8 60491 127.0.0.1 80
__EOM__
  end

  def test_to_h
    log = parse(ModsecurityAuditLogParser.new, CONTENT).shift
    assert_equal(
      {
        timestamp: "23/May/2017:07:44:10 +0000",
        unique_transaction_id: "mcAcAcecAcAcAbAcAcAcAcmo",
        source_ip_address: "123.45.67.8",
        source_port: "60491",
        destination_ip_address: "127.0.0.1",
        destination_port: "80",
        request_headers: "HTTP/1.1 200 OK
Server: 
Content-Type: application/json
Content-Length: 15
Connection: keep-alive

",
        response_headers: "HTTP/1.1 400 Bad Request
Server: Nahi server
Content-Type: application/json
Content-Length: 2
Connection: keep-alive

",
        original_response_body: "\n",
        Message: "Warning. Match of \"eq 0\" against \"REQBODY_ERROR\" required. [file \"/path/to/conf.d/modsecurity.conf\"] [line \"60\"] [id \"200002\"] [msg \"Failed to parse request body.\"] [data \"\"] [severity \"CRITICAL\"]
Warning. Match of \"eq 0\" against \"REQBODY_ERROR\" required. [file \"/path/to/conf.d/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf\"] [line \"157\"] [id \"920130\"] [rev \"1\"] [msg \"Failed to parse request body.\"] [data \"\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [maturity \"9\"] [accuracy \"9\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-protocol\"] [tag \"OWASP_CRS/PROTOCOL_VIOLATION/INVALID_REQ\"] [tag \"CAPEC-272\"]
",
        :"Apache-Handler" => "IIS",
        Stopwatch: "1495601080000788 792314 (- - -)",
        Stopwatch2: "1495601080000788 792314; combined=1704, p1=313, p2=1178, p3=68, p4=105, p5=40, sr=45, sw=0, l=0, gc=0",
        :"Response-Body-Transformed" => "Dechunked",
        Producer: "ModSecurity for nginx (STABLE)/2.9.0 (http://www.modsecurity.org/); OWASP_CRS/3.0.2.",
        Server: "ModSecurity Standalone",
        :"Engine-Mode" => "\"DETECTION_ONLY\"",
        rule_file: "/path/to/conf.d/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
        rule_line: "157",
        rule_id: "920130",
        rule_msg: "Failed to parse request body.",
        rule_data: "",
        rule_severity: "CRITICAL",
        rule_rev: "1",
        rule_ver: "OWASP_CRS/3.0.0",
        rule_maturity: "9",
        rule_accuracy: "9",
        rule_tag: "CAPEC-272"
      },
      log.to_h
    )
  end

private

  def parse(parser, content)
    content.each_line do |line|
      parser.parse(line)
    end
    parser
  end
end
