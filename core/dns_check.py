import ipaddress
import socket


def _result(status, detail, reason):
    return {
        "source": "DNS",
        "status": status,
        "detail": detail,
        "reason": reason
    }


def _internet_works():
    """Return whether a common hostname can be resolved."""
    try:
        socket.getaddrinfo("example.com", None)
        return True
    except (socket.gaierror, UnicodeError, OSError):
        return False


def check_dns(hostname):
    """Check whether a hostname resolves without opening an HTTP connection."""
    temporary_reason = (
        "Your network's DNS did not answer (temporary error). This does not "
        "mean the site is fake or real. Try again or use another network."
    )
    unable_reason = (
        "The lookup could not be completed, so nothing can be said about "
        "this domain."
    )

    if not hostname:
        return _result(
            "UNABLE_TO_VERIFY", "Hostname is empty.", unable_reason
        )

    try:
        ipaddress.ip_address(hostname)
        return _result(
            "SKIPPED_IP",
            "Hostname is an IP address; DNS lookup was skipped.",
            "The URL uses an IP address, so there is no domain name to look up."
        )
    except ValueError:
        pass

    try:
        records = socket.getaddrinfo(hostname, None)
        return _result(
            "RESOLVES",
            "Found " + str(len(records)) + " address records.",
            "The domain name exists and points to a server. "
            "This does not prove the site is safe."
        )
    except socket.gaierror as error:
        not_found_codes = {
            getattr(socket, "EAI_NONAME", None),
            11001,
            11004
        }
        if error.errno in not_found_codes:
            if _internet_works():
                return _result(
                    "DOES_NOT_RESOLVE",
                    "Hostname was not found in DNS.",
                    "This name has no active DNS records, so the site cannot "
                    "be reached. Common causes: a typo, an expired domain, or "
                    "a site that was taken down."
                )
            return _result(
                "UNABLE_TO_VERIFY",
                "Your internet or DNS seems unavailable.",
                temporary_reason
            )
        temporary_codes = {
            getattr(socket, "EAI_AGAIN", None),
            11002
        }
        reason = (
            temporary_reason
            if error.errno in temporary_codes
            else unable_reason
        )
        return _result(
            "UNABLE_TO_VERIFY",
            "DNS lookup failed: " + str(error),
            reason
        )
    except (UnicodeError, OSError) as error:
        return _result(
            "UNABLE_TO_VERIFY",
            "DNS lookup failed: " + str(error),
            unable_reason
        )
