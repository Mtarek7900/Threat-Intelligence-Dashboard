package io.github.mtarek7900.tid.indicator;

import io.github.mtarek7900.tid.indicator.ParseResult.Accepted;
import io.github.mtarek7900.tid.indicator.ParseResult.Rejected;
import io.github.mtarek7900.tid.indicator.ParseResult.Rejection;
import java.net.IDN;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Turns whatever the Analyst pasted into a normalised {@link Indicator}, or says why it can't. */
public final class IndicatorParser {

    private static final Pattern HEX = Pattern.compile("[0-9a-f]+");
    private static final Pattern HEXTET = Pattern.compile("[0-9a-f]{1,4}");
    private static final Pattern OCTET = Pattern.compile("0|[1-9]\\d{0,2}");
    private static final Pattern DOMAIN_LABEL = Pattern.compile("[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?");
    private static final Pattern TOP_LEVEL_LABEL = Pattern.compile("[a-z]{2,63}|xn--[a-z0-9-]+");
    private static final Pattern URL_SCHEME = Pattern.compile("[a-z][a-z0-9+.-]*://.*");

    private static final String BLANK_MESSAGE = "Paste an IP address, domain or file hash to look up.";
    private static final String URL_MESSAGE =
            "URLs aren't supported yet. Look up the URL's domain or IP address instead.";
    private static final String UNRECOGNISED_MESSAGE =
            "That isn't an IP address, domain or file hash. Paste an IPv4 or IPv6 address,"
                    + " a domain such as example.com, or an MD5, SHA-1 or SHA-256 file hash.";

    /** IANA special-purpose ranges that no Source has anything useful to say about. */
    private static final List<ReservedRange> RESERVED_RANGES = List.of(
            ReservedRange.of("0.0.0.0/8", "a 'this network' address"),
            ReservedRange.of("10.0.0.0/8", "a private address"),
            ReservedRange.of("100.64.0.0/10", "a shared (carrier-grade NAT) address"),
            ReservedRange.of("127.0.0.0/8", "a loopback address"),
            ReservedRange.of("169.254.0.0/16", "a link-local address"),
            ReservedRange.of("172.16.0.0/12", "a private address"),
            ReservedRange.of("192.0.0.0/24", "an IETF protocol address"),
            ReservedRange.of("192.0.2.0/24", "a documentation address"),
            ReservedRange.of("192.88.99.0/24", "a 6to4 relay anycast address"),
            ReservedRange.of("192.168.0.0/16", "a private address"),
            ReservedRange.of("198.18.0.0/15", "a benchmarking address"),
            ReservedRange.of("198.51.100.0/24", "a documentation address"),
            ReservedRange.of("203.0.113.0/24", "a documentation address"),
            ReservedRange.of("224.0.0.0/4", "a multicast address"),
            ReservedRange.of("240.0.0.0/4", "a reserved address"),
            ReservedRange.of("::/128", "an unspecified address"),
            ReservedRange.of("::1/128", "a loopback address"),
            ReservedRange.of("::ffff:0:0/96", "an IPv4-mapped address"),
            ReservedRange.of("100::/64", "a discard address"),
            ReservedRange.of("2001::/23", "an IETF protocol address"),
            ReservedRange.of("2001:db8::/32", "a documentation address"),
            ReservedRange.of("3fff::/20", "a documentation address"),
            ReservedRange.of("fc00::/7", "a unique local (private) address"),
            ReservedRange.of("fe80::/10", "a link-local address"),
            ReservedRange.of("fec0::/10", "a site-local address"),
            ReservedRange.of("ff00::/8", "a multicast address"));

    /** IPv6 addresses outside this are unallocated or special-purpose, so they're rejected too. */
    private static final ReservedRange GLOBAL_UNICAST =
            ReservedRange.of("2000::/3", "outside the global unicast range");

    private IndicatorParser() {}

    public static ParseResult parse(String raw) {
        var value = refang(raw.strip()).toLowerCase(Locale.ROOT);
        if (value.isEmpty()) {
            return new Rejected(Rejection.UNRECOGNISED, BLANK_MESSAGE);
        }

        if (isHash(value)) {
            return accept(value, IndicatorType.FILE_HASH);
        }
        var ipv4 = parseIpv4(value);
        if (ipv4 != null) {
            return acceptPublicIp(value, toBytes(ipv4, 8), value);
        }
        var ipv6 = parseIpv6(value);
        if (ipv6 != null) {
            return acceptPublicIp(value, toBytes(ipv6, 16), formatIpv6(ipv6));
        }
        var domain = normaliseDomain(value);
        if (domain != null) {
            return accept(domain, IndicatorType.DOMAIN);
        }
        if (isUrl(value)) {
            return new Rejected(Rejection.URL_NOT_SUPPORTED, URL_MESSAGE);
        }
        return new Rejected(Rejection.UNRECOGNISED, UNRECOGNISED_MESSAGE);
    }

    private static ParseResult accept(String value, IndicatorType type) {
        return new Accepted(new Indicator(value, type));
    }

    /** {@code refanged} is the address as the Analyst wrote it, for the rejection message. */
    private static ParseResult acceptPublicIp(String refanged, byte[] address, String normalised) {
        for (var range : RESERVED_RANGES) {
            if (range.contains(address)) {
                return rejectReserved(refanged, range);
            }
        }
        if (address.length == 16 && !GLOBAL_UNICAST.contains(address)) {
            return rejectReserved(refanged, GLOBAL_UNICAST);
        }
        return accept(normalised, IndicatorType.IP_ADDRESS);
    }

    private static ParseResult rejectReserved(String refanged, ReservedRange range) {
        return new Rejected(
                Rejection.RESERVED_IP_ADDRESS,
                refanged + " is " + range.description() + " (" + range.cidr() + ")."
                        + " Sources only know about public IP addresses.");
    }

    private static String refang(String value) {
        return value.replaceAll("(?i)\\[\\.]|\\(\\.\\)|\\[dot]", ".")
                .replace("[:]", ":")
                .replaceFirst("(?i)^hxxp(s?)://", "http$1://");
    }

    /**
     * Has a scheme, like https://evil.com, or a path after a host and optional port, like
     * evil.com:8080/login or [2001:db8::1]/login.
     */
    private static boolean isUrl(String value) {
        if (URL_SCHEME.matcher(value).matches()) {
            return true;
        }
        var slash = value.indexOf('/');
        if (slash < 0) {
            return false;
        }
        var host = value.substring(0, slash);
        if (host.startsWith("[") && host.endsWith("]")) {
            return parseIpv6(host.substring(1, host.length() - 1)) != null;
        }
        host = host.replaceFirst(":\\d{1,5}$", "");
        return parseIpv4(host) != null || normaliseDomain(host) != null;
    }

    private static boolean isHash(String value) {
        var length = value.length();
        return (length == 32 || length == 40 || length == 64) && HEX.matcher(value).matches();
    }

    /** The four octets of a dotted-decimal IPv4 address, or null if it isn't one. */
    private static int[] parseIpv4(String value) {
        var parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        var octets = new int[4];
        for (int i = 0; i < 4; i++) {
            if (!OCTET.matcher(parts[i]).matches()) {
                return null;
            }
            octets[i] = Integer.parseInt(parts[i]);
            if (octets[i] > 255) {
                return null;
            }
        }
        return octets;
    }

    /** The eight 16-bit groups of an IPv6 address, or null if it isn't one. */
    private static int[] parseIpv6(String value) {
        if (!value.contains(":")) {
            return null;
        }
        var gap = value.indexOf("::");
        if (gap != value.lastIndexOf("::")) {
            return null;
        }
        List<Integer> head = gap < 0 ? hextets(value, true) : hextets(value.substring(0, gap), false);
        List<Integer> tail = gap < 0 ? List.of() : hextets(value.substring(gap + 2), true);
        if (head == null || tail == null) {
            return null;
        }
        var explicit = head.size() + tail.size();
        if (gap < 0 ? explicit != 8 : explicit > 7) {
            return null;
        }
        var groups = new int[8];
        for (int i = 0; i < head.size(); i++) {
            groups[i] = head.get(i);
        }
        for (int i = 0; i < tail.size(); i++) {
            groups[8 - tail.size() + i] = tail.get(i);
        }
        return groups;
    }

    /** Colon-separated groups; the last may be an embedded IPv4 address when allowed. */
    private static List<Integer> hextets(String value, boolean ipv4AllowedLast) {
        var groups = new ArrayList<Integer>();
        if (value.isEmpty()) {
            return groups;
        }
        var parts = value.split(":", -1);
        for (int i = 0; i < parts.length; i++) {
            var part = parts[i];
            if (HEXTET.matcher(part).matches()) {
                groups.add(Integer.parseInt(part, 16));
                continue;
            }
            var ipv4 = i == parts.length - 1 && ipv4AllowedLast ? parseIpv4(part) : null;
            if (ipv4 == null) {
                return null;
            }
            groups.add(ipv4[0] << 8 | ipv4[1]);
            groups.add(ipv4[2] << 8 | ipv4[3]);
        }
        return groups;
    }

    /** RFC 5952 text form: lower-case, no leading zeros, longest run of 2+ zero groups as "::". */
    private static String formatIpv6(int[] groups) {
        int bestStart = -1, bestLength = 1;
        for (int i = 0; i < 8; ) {
            int j = i;
            while (j < 8 && groups[j] == 0) {
                j++;
            }
            if (j - i > bestLength) {
                bestStart = i;
                bestLength = j - i;
            }
            i = j == i ? i + 1 : j;
        }
        var text = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                text.append("::");
                i += bestLength - 1;
                continue;
            }
            if (!text.isEmpty() && text.charAt(text.length() - 1) != ':') {
                text.append(':');
            }
            text.append(Integer.toHexString(groups[i]));
        }
        return text.toString();
    }

    /** Packs octets (8-bit) or IPv6 groups (16-bit) into network-order bytes. */
    private static byte[] toBytes(int[] parts, int bitsPerPart) {
        var bytesPerPart = bitsPerPart / 8;
        var bytes = new byte[parts.length * bytesPerPart];
        for (int i = 0; i < parts.length; i++) {
            for (int b = 0; b < bytesPerPart; b++) {
                bytes[i * bytesPerPart + b] = (byte) (parts[i] >> (8 * (bytesPerPart - 1 - b)));
            }
        }
        return bytes;
    }

    private record ReservedRange(String cidr, byte[] network, int prefixLength, String description) {

        static ReservedRange of(String cidr, String description) {
            var slash = cidr.indexOf('/');
            var address = cidr.substring(0, slash);
            var ipv4 = parseIpv4(address);
            var network = ipv4 != null ? toBytes(ipv4, 8) : toBytes(parseIpv6(address), 16);
            return new ReservedRange(cidr, network, Integer.parseInt(cidr.substring(slash + 1)), description);
        }

        boolean contains(byte[] address) {
            if (address.length != network.length) {
                return false;
            }
            for (int bit = 0; bit < prefixLength; bit++) {
                var mask = 0x80 >> (bit % 8);
                if ((address[bit / 8] & mask) != (network[bit / 8] & mask)) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * The domain in ASCII (punycode) form without any trailing root dot, or null if it isn't a
     * valid domain name.
     */
    private static String normaliseDomain(String value) {
        var domain = value.endsWith(".") ? value.substring(0, value.length() - 1) : value;
        try {
            domain = IDN.toASCII(domain, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException notADomain) {
            return null;
        }
        if (domain.isEmpty() || domain.length() > 253) {
            return null;
        }
        var labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            return null;
        }
        for (var label : labels) {
            if (!DOMAIN_LABEL.matcher(label).matches()) {
                return null;
            }
        }
        var tld = labels[labels.length - 1];
        return TOP_LEVEL_LABEL.matcher(tld).matches() ? domain : null;
    }
}
