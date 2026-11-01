import ipaddress
from urllib.parse import urlsplit
from dataclasses import dataclass


@dataclass
class ParsedURL:
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    path: str
    query: str
    fragment: str
    port: int | None
    is_ip_address: bool
    is_valid: bool
    errors: list


def parse_url(raw_url):
    """
    Normalize and parse a URL without opening it.
    """

    if not isinstance(raw_url, str):
        return ParsedURL(
            str(raw_url), "", "", "", "", "",
            "", None, False, False,
            ["URL must be text."]
        )

    original = raw_url.strip()

    if not original:
        return ParsedURL(
            original, "", "", "", "", "",
            "", None, False, False,
            ["URL cannot be empty."]
        )

    # Reject whitespace inside a URL.
    if any(char.isspace() for char in original):
        return ParsedURL(
            original, original, "", "", "", "",
            "", None, False, False,
            ["URL contains whitespace."]
        )

    # Allow users to enter a domain without a scheme.
    normalized = original

    if "://" not in normalized:
        normalized = "https://" + normalized

    errors = []

    try:
        parsed = urlsplit(normalized)

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname

        if scheme not in ("http", "https"):
            errors.append("Only HTTP and HTTPS URLs are supported.")

        if not hostname:
            errors.append("Hostname could not be identified.")
            hostname = ""

        hostname = hostname.lower().rstrip(".")

        # Validate hostname or IP address.
        is_ip = False

        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                is_ip = False

                try:
                    hostname.encode("idna")
                except UnicodeError:
                    errors.append("Invalid internationalized hostname.")

                if not hostname or len(hostname) > 253:
                    errors.append("Invalid hostname length.")

                labels = hostname.split(".")

                for label in labels:
                    if (
                        not label
                        or len(label) > 63
                        or label.startswith("-")
                        or label.endswith("-")
                    ):
                        errors.append("Invalid hostname label.")
                        break

                    if not all(
                        char.isalnum() or char == "-"
                        for char in label
                    ):
                        errors.append("Hostname contains invalid characters.")
                        break

        # Accessing parsed.port can raise ValueError.
        try:
            port = parsed.port
        except ValueError:
            port = None
            errors.append("Invalid port number.")

        if parsed.username is not None or parsed.password is not None:
            # Credentials are allowed to be parsed,
            # but the detection engine will flag them.
            pass

        return ParsedURL(
            original_url=original,
            normalized_url=normalized,
            scheme=scheme,
            hostname=hostname,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
            port=port,
            is_ip_address=is_ip,
            is_valid=len(errors) == 0,
            errors=errors
        )

    except ValueError:
        return ParsedURL(
            original, normalized, "", "", "", "",
            "", None, False, False,
            ["Malformed URL."]
        )