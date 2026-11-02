import re
from urllib.parse import urlparse


URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

IP_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)

HASH_REGEX = re.compile(
    r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
)

LINUX_PATH_REGEX = re.compile(r"(?:/[\w.\-]+)+(?:\.[\w.\-]+)?")

FILENAME_REGEX = re.compile(
    r"\b[\w.\-]+\.(?:sh|py|pl|bin|elf|txt|zip|tar|gz|exe)\b",
    re.IGNORECASE
)


TRAILING_CHARS = ".,;:)]}\"'"


def clean_indicator(value: str) -> str:
    return value.strip().rstrip(TRAILING_CHARS)


def normalize_url(url: str) -> str:
    cleaned = clean_indicator(url)

    parsed = urlparse(cleaned)

    if not parsed.scheme or not parsed.netloc:
        return cleaned

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path

    return f"{scheme}://{netloc}{path}"


def extract_iocs(event: dict) -> dict:
    text = " ".join(
        str(value)
        for value in [
            event.get("input"),
            event.get("message"),
            event.get("url"),
            event.get("outfile"),
            event.get("ttylog"),
            event.get("shasum"),
        ]
        if value
    )

    urls = sorted(set(
        normalize_url(url)
        for url in URL_REGEX.findall(text)
    ))

    domains = sorted(set(
        urlparse(url).netloc.lower()
        for url in urls
        if urlparse(url).netloc
    ))

    ips = sorted(set(
        clean_indicator(ip)
        for ip in IP_REGEX.findall(text)
    ))

    hashes = sorted(set(
        clean_indicator(hash_value).lower()
        for hash_value in HASH_REGEX.findall(text)
    ))

    file_paths = sorted(set(
        clean_indicator(path)
        for path in LINUX_PATH_REGEX.findall(text)
    ))

    filenames = sorted(set(
        clean_indicator(filename)
        for filename in FILENAME_REGEX.findall(text)
    ))

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "hashes": hashes,
        "file_paths": file_paths,
        "filenames": filenames,
    }