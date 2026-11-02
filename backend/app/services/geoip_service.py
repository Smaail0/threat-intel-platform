import ipaddress
from functools import lru_cache
from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError

GEOIP_DIR = Path(__file__).resolve().parents[2] / "data" / "geoip"
CITY_DB_PATH = GEOIP_DIR / "GeoLite2-City.mmdb"
ASN_DB_PATH = GEOIP_DIR / "GeoLite2-ASN.mmdb"


@lru_cache(maxsize=1)
def get_city_reader():
    return geoip2.database.Reader(str(CITY_DB_PATH))


@lru_cache(maxsize=1)
def get_asn_reader():
    return geoip2.database.Reader(str(ASN_DB_PATH))


def enrich_ip(ip: str | None) -> dict:
    if not ip:
        return {"ip": None, "type": "unknown", "is_public": False}

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "type": "invalid", "is_public": False}

    if ip_obj.is_loopback:
        return {
            "ip": ip,
            "type": "loopback",
            "is_public": False,
            "label": "Localhost"
        }

    if ip_obj.is_private:
        return {
            "ip": ip,
            "type": "private",
            "is_public": False,
            "label": "Private/Internal IP"
        }

    geo = {
        "ip": ip,
        "type": "public",
        "is_public": True,
        "label": "Public IP",
        "country": None,
        "country_iso": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "organization": None
    }

    try:
        city = get_city_reader().city(ip)
        geo["country"] = city.country.name
        geo["country_iso"] = city.country.iso_code
        geo["city"] = city.city.name
        geo["latitude"] = city.location.latitude
        geo["longitude"] = city.location.longitude
    except AddressNotFoundError:
        pass
    except FileNotFoundError:
        geo["city_db_missing"] = True

    try:
        asn = get_asn_reader().asn(ip)
        geo["asn"] = asn.autonomous_system_number
        geo["organization"] = asn.autonomous_system_organization
    except AddressNotFoundError:
        pass
    except FileNotFoundError:
        geo["asn_db_missing"] = True

    return geo