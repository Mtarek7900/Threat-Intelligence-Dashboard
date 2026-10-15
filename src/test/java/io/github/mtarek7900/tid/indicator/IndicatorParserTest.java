package io.github.mtarek7900.tid.indicator;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mtarek7900.tid.indicator.ParseResult.Accepted;
import io.github.mtarek7900.tid.indicator.ParseResult.Rejected;
import io.github.mtarek7900.tid.indicator.ParseResult.Rejection;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class IndicatorParserTest {

    @ParameterizedTest(name = "[{0}] -> {1} ({2})")
    @CsvSource(delimiter = '|', textBlock = """
            8.8.8.8                    | 8.8.8.8                    | IP_ADDRESS
            evil.com                   | evil.com                   | DOMAIN
            d41d8cd98f00b204e9800998ecf8427e | d41d8cd98f00b204e9800998ecf8427e | FILE_HASH
            """)
    void acceptsAnIndicatorAndWorksOutItsType(String raw, String normalised, IndicatorType type) {
        assertThat(IndicatorParser.parse(raw)).isEqualTo(new Accepted(new Indicator(normalised, type)));
    }

    @ParameterizedTest(name = "[{0}] -> {1}")
    @CsvSource(delimiter = '|', ignoreLeadingAndTrailingWhitespace = false, textBlock = """
            1.2.3[.]4|1.2.3.4
            1[.]2[.]3[.]4|1.2.3.4
            1.2.3(.)4|1.2.3.4
            1.2.3[dot]4|1.2.3.4
            evil[.]com|evil.com
            evil(.)com|evil.com
            evil[dot]com|evil.com
            evil[DOT]com|evil.com
            sub[.]evil[.]co[.]uk|sub.evil.co.uk
            2001:4860:4860[:]:8888|2001:4860:4860::8888
            """)
    void refangsDefangedIndicators(String raw, String normalised) {
        assertThat(IndicatorParser.parse(raw))
                .isInstanceOfSatisfying(Accepted.class, accepted -> assertThat(
                                accepted.indicator().value())
                        .isEqualTo(normalised));
    }

    @ParameterizedTest(name = "[{0}] -> {1}")
    @CsvSource(delimiter = '|', ignoreLeadingAndTrailingWhitespace = false, textBlock = """
            '  evil.com  '|evil.com
            '\tevil.com\n'|evil.com
            EVIL.com|evil.com
            ' EVIL.com '|evil.com
            Sub.Evil.COM|sub.evil.com
            evil.com.|evil.com
            D41D8CD98F00B204E9800998ECF8427E|d41d8cd98f00b204e9800998ecf8427e
            ' 8.8.8.8 '|8.8.8.8
            2001:4860:4860:0:0:0:0:8888|2001:4860:4860::8888
            2001:4860:4860:0000:0000:0000:0000:8888|2001:4860:4860::8888
            2001:4860:4860::8888|2001:4860:4860::8888
            2001:0:4860:0:0:1:0:1|2001:0:4860::1:0:1
            """)
    void normalisesWhitespaceAndCase(String raw, String normalised) {
        assertThat(IndicatorParser.parse(raw.translateEscapes()))
                .isInstanceOfSatisfying(Accepted.class, accepted -> assertThat(
                                accepted.indicator().value())
                        .isEqualTo(normalised));
    }

    @ParameterizedTest(name = "[{0}] is {1}")
    @CsvSource(delimiter = '|', textBlock = """
            0.0.0.0             | a 'this network' address (0.0.0.0/8)
            0.255.255.255       | a 'this network' address (0.0.0.0/8)
            10.0.0.1            | a private address (10.0.0.0/8)
            10.255.255.255      | a private address (10.0.0.0/8)
            100.64.0.1          | a shared (carrier-grade NAT) address (100.64.0.0/10)
            100.127.255.255     | a shared (carrier-grade NAT) address (100.64.0.0/10)
            127.0.0.1           | a loopback address (127.0.0.0/8)
            169.254.169.254     | a link-local address (169.254.0.0/16)
            172.16.0.1          | a private address (172.16.0.0/12)
            172.31.255.255      | a private address (172.16.0.0/12)
            192.0.0.8           | an IETF protocol address (192.0.0.0/24)
            192.0.2.1           | a documentation address (192.0.2.0/24)
            192.168.1.1         | a private address (192.168.0.0/16)
            198.18.0.1          | a benchmarking address (198.18.0.0/15)
            198.19.255.255      | a benchmarking address (198.18.0.0/15)
            198.51.100.7        | a documentation address (198.51.100.0/24)
            203.0.113.9         | a documentation address (203.0.113.0/24)
            224.0.0.251         | a multicast address (224.0.0.0/4)
            239.255.255.250     | a multicast address (224.0.0.0/4)
            240.0.0.1           | a reserved address (240.0.0.0/4)
            255.255.255.255     | a reserved address (240.0.0.0/4)
            ::                  | an unspecified address (::/128)
            ::1                 | a loopback address (::1/128)
            ::ffff:8.8.8.8      | an IPv4-mapped address (::ffff:0:0/96)
            100::1              | a discard address (100::/64)
            2001:db8::1         | a documentation address (2001:db8::/32)
            3fff::1             | a documentation address (3fff::/20)
            fc00::1             | a unique local (private) address (fc00::/7)
            fd12:3456:789a::1   | a unique local (private) address (fc00::/7)
            fe80::1             | a link-local address (fe80::/10)
            febf::1             | a link-local address (fe80::/10)
            fec0::1             | a site-local address (fec0::/10)
            ff02::1             | a multicast address (ff00::/8)
            """)
    void rejectsReservedIpAddresses(String raw, String description) {
        assertThat(IndicatorParser.parse(raw))
                .isEqualTo(new Rejected(
                        Rejection.RESERVED_IP_ADDRESS,
                        raw + " is " + description
                                + ". Sources only know about public IP addresses."));
    }

    @ParameterizedTest(name = "[{0}]")
    @CsvSource(textBlock = """
            9.255.255.255
            11.0.0.0
            100.63.255.255
            100.128.0.0
            126.255.255.255
            128.0.0.0
            169.253.255.255
            172.15.255.255
            172.32.0.0
            192.0.1.0
            192.167.255.255
            192.169.0.0
            198.17.255.255
            198.20.0.0
            223.255.255.255
            2001:4860:4860::8888
            2606:4700:4700::1111
            2001:db9::1
            fbff::1
            """)
    void acceptsPublicIpAddressesNextToReservedRanges(String raw) {
        assertThat(IndicatorParser.parse(raw)).isEqualTo(new Accepted(new Indicator(raw, IndicatorType.IP_ADDRESS)));
    }

    @ParameterizedTest(name = "[{0}] -> {1} ({2})")
    @CsvSource(delimiter = '|', textBlock = """
            d41d8cd98f00b204e9800998ecf8427e | d41d8cd98f00b204e9800998ecf8427e | FILE_HASH
            da39a3ee5e6b4b0d3255bfef95601890afd80709 | da39a3ee5e6b4b0d3255bfef95601890afd80709 | FILE_HASH
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | FILE_HASH
            E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | FILE_HASH
            a.co                       | a.co                       | DOMAIN
            my-site.example.org        | my-site.example.org        | DOMAIN
            _dmarc.evil.com            | _dmarc.evil.com            | DOMAIN
            1.2.3.4.evil.com           | 1.2.3.4.evil.com           | DOMAIN
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com | DOMAIN
            xn--bcher-kva.de           | xn--bcher-kva.de           | DOMAIN
            Bücher.de                  | xn--bcher-kva.de           | DOMAIN
            evil.xn--p1ai              | evil.xn--p1ai              | DOMAIN
            deadbeef.com               | deadbeef.com               | DOMAIN
            """)
    void acceptsEdgeCaseHashesAndDomains(String raw, String normalised, IndicatorType type) {
        assertThat(IndicatorParser.parse(raw)).isEqualTo(new Accepted(new Indicator(normalised, type)));
    }

    @ParameterizedTest(name = "[{0}]")
    @CsvSource(delimiter = '|', textBlock = """
            http://evil.com
            https://evil.com/login
            HTTPS://EVIL.COM
            hxxp://evil[.]com
            hxxps://evil[.]com/payload.exe
            hxxps[:]//evil[.]com
            HXXP[:]//1.2.3[.]4/
            ftp://files.evil.com
            evil.com/login.php
            evil[.]com/login
            1.2.3.4/admin
            """)
    void rejectsUrlsWithASpecificMessage(String raw) {
        assertThat(IndicatorParser.parse(raw))
                .isEqualTo(new Rejected(
                        Rejection.URL_NOT_SUPPORTED,
                        "URLs aren't supported yet. Look up the URL's domain or IP address instead."));
    }

    @ParameterizedTest(name = "[{0}]")
    @CsvSource(delimiter = '|', ignoreLeadingAndTrailingWhitespace = false, textBlock = """
            hello
            evil
            evil.123
            evil.c
            -evil.com
            evil-.com
            evil..com
            .evil.com
            evil com
            user@evil.com
            evil.com:8080
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com
            1.2.3
            1.2.3.4.5
            256.1.1.1
            01.2.3.4
            1:2:3:4:5:6:7:8:9
            1::2::3
            gggg::1
            2001:db8::1%eth0
            d41d8cd98f00b204e9800998ecf8427
            d41d8cd98f00b204e9800998ecf8427e0
            da39a3ee5e6b4b0d3255bfef95601890afd8070
            da39a3ee5e6b4b0d3255bfef95601890afd807090
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            g41d8cd98f00b204e9800998ecf8427e
            """)
    void rejectsAnythingElseWithAMessageSayingWhatIsAccepted(String raw) {
        assertThat(IndicatorParser.parse(raw))
                .isEqualTo(new Rejected(
                        Rejection.UNRECOGNISED,
                        "That isn't an IP address, domain or file hash. Paste an IPv4 or IPv6 address,"
                                + " a domain such as example.com, or an MD5, SHA-1 or SHA-256 file hash."));
    }

    @ParameterizedTest(name = "[{0}]")
    @CsvSource(delimiter = '|', ignoreLeadingAndTrailingWhitespace = false, textBlock = """
            ''
            '   '
            """)
    void asksForAnIndicatorWhenTheInputIsBlank(String raw) {
        assertThat(IndicatorParser.parse(raw))
                .isEqualTo(new Rejected(
                        Rejection.UNRECOGNISED, "Paste an IP address, domain or file hash to look up."));
    }
}
