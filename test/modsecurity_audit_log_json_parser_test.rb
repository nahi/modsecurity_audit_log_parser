require 'test_helper'

class ModsecurityAuditLogJSONParserTest < Minitest::Test
  LOG_1 = <<'__EOM__'
{
  "transaction": {
    "client_ip": "127.0.0.1",
    "time_stamp": "Wed Jul 12 02:47:03 2017",
    "server_id": "aaca53145586a533f366000989e875fc5d8ac8de",
    "client_port": 34992,
    "host_ip": "127.0.0.1",
    "host_port": 5140,
    "id": "149982762313.623639",
    "request": {
      "method": "GET",
      "http_version": 1.1,
      "uri": "/",
      "headers": {
        "Host": "localhost:5140",
        "Accept": "*/*",
        "User-Agent": "Nikto"
      }
    },
    "response": {
      "http_code": 400,
      "headers": {
        "Server": "",
        "Date": "Wed, 12 Jul 2017 02:47:04 GMT",
        "Content-Length": "96",
        "Content-Type": "application/json",
        "Connection": "keep-alive"
      }
    },
    "producer": {
      "modsecurity": "ModSecurity v3.0.0-alpha (Linux)",
      "connector": "ModSecurity-nginx v0.1.1-beta",
      "secrules_engine": "DetectionOnly",
      "components": [
        "OWASP_CRS/3.0.2\""
      ]
    },
    "messages": [
      {
        "message": "Found User-Agent associated with security scanner",
        "details": {
          "match": "Matched \"Operator `PmFromFile' with parameter `scanners-user-agents.data' against variable `REQUEST_HEADERS:User-Agent' (Value: `Nikto' )",
          "reference": "o0,5v60,5t:lowercase",
          "ruleId": "913100",
          "file": "/path/to/owasp-modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf",
          "lineNumber": "17",
          "data": "Matched Data: nikto found within REQUEST_HEADERS:User-Agent: Nikto",
          "severity": "2",
          "ver": "OWASP_CRS/3.0.0",
          "rev": "2",
          "tags": [
            "application-multi",
            "language-multi",
            "platform-multi",
            "attack-reputation-scanner",
            "OWASP_CRS/AUTOMATION/SECURITY_SCANNER",
            "WASCTC/WASC-21",
            "OWASP_TOP_10/A7",
            "PCI/6.5.10"
          ],
          "maturity": "9",
          "accuracy": "9"
        }
      },
      {
        "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
        "details": {
          "match": "Matched \"Operator `Ge' with parameter `%{tx.inbound_anomaly_score_threshold}' against variable `TX:ANOMALY_SCORE' (Value: `5' )",
          "reference": "",
          "ruleId": "949110",
          "file": "/path/to/owasp-modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
          "lineNumber": "36",
          "data": "",
          "severity": "2",
          "ver": "",
          "rev": "",
          "tags": [
            "application-multi",
            "language-multi",
            "platform-multi",
            "attack-generic"
          ],
          "maturity": "0",
          "accuracy": "0"
        }
      },
      {
        "message": "Inbound Anomaly Score Exceeded (Total Inbound Score: 5 - SQLI=0,XSS=0,RFI=0,LFI=0,RCE=0,PHPI=0,HTTP=0,SESS=0): Found User-Agent associated with security scanner'",
        "details": {
          "match": "Matched \"Operator `Ge' with parameter `%{tx.inbound_anomaly_score_threshold}' against variable `TX:INBOUND_ANOMALY_SCORE' (Value: `5' )",
          "reference": "",
          "ruleId": "980130",
          "file": "/path/to/owasp-modsecurity-crs/rules/RESPONSE-980-CORRELATION.conf",
          "lineNumber": "61",
          "data": "",
          "severity": "0",
          "ver": "",
          "rev": "",
          "tags": [
            "event-correlation"
          ],
          "maturity": "0",
          "accuracy": "0"
        }
      }
    ]
  }
}
__EOM__

  def test_parse
    parser = parse(ModsecurityAuditLogParser.new(format: 'JSON'), LOG_1)
    log = parser.shift
    assert_equal '149982762313.623639', log.id
    # Curent JSON log does not have TZ. Parsing depends on environment TZ config.
    assert_equal Time.parse('Wed Jul 12 02:47:03 2017').to_i, log.time
    assert_equal 25, log.to_h.size
  end

  def test_to_h
    parser = parse(ModsecurityAuditLogParser.new(format: 'JSON'), LOG_1)
    hash = parser.shift.to_h
    assert_equal '149982762313.623639', hash[:id]
    assert_equal Time.parse('Wed Jul 12 02:47:03 2017').to_i, hash[:time]
    assert_equal 'Wed Jul 12 02:47:03 2017', hash[:time_stamp]
    assert_equal '127.0.0.1', hash[:client_ip]
    assert_equal 34992, hash[:client_port]
    assert_equal '127.0.0.1', hash[:host_ip]
    assert_equal 5140, hash[:host_port]
    assert_equal 'Nikto', hash[:request][:headers][:'User-Agent']
    assert_equal '96', hash[:response][:headers][:'Content-Length']
    assert_equal 'ModSecurity v3.0.0-alpha (Linux); OWASP_CRS/3.0.2"', hash[:producer]
    assert_equal 'ModSecurity-nginx v0.1.1-beta', hash[:connector]
    assert_equal 'DetectionOnly', hash[:secrules_engine]
    assert_equal 'Found User-Agent associated with security scanner', hash[:rule_message]
    assert_equal '913100', hash[:rule_id]
    assert_equal 'OWASP_CRS/3.0.0', hash[:rule_ver]
    assert_equal '2', hash[:rule_rev]
    assert_equal 'PCI/6.5.10', hash[:rule_tag]
    assert_equal 'application-multi, language-multi, platform-multi, attack-reputation-scanner, OWASP_CRS/AUTOMATION/SECURITY_SCANNER, WASCTC/WASC-21, OWASP_TOP_10/A7, PCI/6.5.10', hash[:rule_tags]
    assert_equal '/path/to/owasp-modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf', hash[:rule_file]
    assert_equal '17', hash[:rule_line_number]
    assert_equal 'Matched Data: nikto found within REQUEST_HEADERS:User-Agent: Nikto', hash[:rule_data]
    assert_equal '2', hash[:rule_severity]
    assert_equal '9', hash[:rule_maturity]
    assert_equal '9', hash[:rule_accuracy]
    assert_equal 'event-correlation', hash[:messages].last[:details][:tags].first
  end

  def test_ignore_incomplete_str
    parser = ModsecurityAuditLogParser.new(format: 'JSON').parse(LOG_1[0, 100])
    assert_nil parser.shift
    parser.parse(LOG_1[101, LOG_1.length - 100])
    log = parser.shift
    assert_equal '149982762313.623639', log.id
  end

private

  def parse(parser, content)
    content.each_line do |line|
      parser.parse(line)
    end
    parser
  end
end
