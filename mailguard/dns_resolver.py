"""DNS resolution module supporting live queries, in-memory caching, and deterministic offline fixture resolution."""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import dns.exception
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)


class DNSLookupError(Exception):
    """Base exception for DNS resolution failures."""
    pass


class DNSTimeoutError(DNSLookupError):
    """DNS query timed out."""
    pass


class DNSNXDomainError(DNSLookupError):
    """Domain does not exist."""
    pass


class DNSNoAnswerError(DNSLookupError):
    """Query succeeded but no matching record type was found."""
    pass


class BaseDNSResolver(ABC):
    """Abstract base class for DNS resolvers."""

    @abstractmethod
    def query_txt(self, domain: str) -> List[str]:
        """Query TXT records for a domain."""
        pass

    @abstractmethod
    def query_a(self, domain: str) -> List[str]:
        """Query IPv4 A records for a domain."""
        pass

    @abstractmethod
    def query_mx(self, domain: str) -> List[Tuple[int, str]]:
        """Query MX records for a domain, returning list of (preference, host)."""
        pass

    @abstractmethod
    def spf_dns_lookup(self, name: str, qtype: str, tcpfallback: bool = True, timeout: int = 20) -> List[Any]:
        """Compatibility callback for pyspf DNS lookup."""
        pass

    @abstractmethod
    def dkim_dns_lookup(self, name: Union[bytes, str], timeout: int = 5) -> bytes:
        """Compatibility callback for dkimpy TXT key lookup."""
        pass


class OfflineDNSResolver(BaseDNSResolver):
    """Deterministic offline DNS resolver powered by JSON fixture data.
    
    Guarantees that no external network traffic or DNS queries are generated.
    """

    def __init__(self, fixtures: Optional[Dict[str, Any]] = None, fixtures_path: Optional[str] = None):
        self.records: Dict[str, Dict[str, Any]] = {}
        if fixtures:
            self._load_dict(fixtures)
        elif fixtures_path and Path(fixtures_path).is_file():
            self._load_file(fixtures_path)

    def _normalize_name(self, name: str) -> str:
        return name.strip().rstrip(".").lower()

    def _load_dict(self, data: Dict[str, Any]) -> None:
        for domain, recs in data.items():
            norm_domain = self._normalize_name(domain)
            self.records[norm_domain] = {}
            for qtype, vals in recs.items():
                self.records[norm_domain][qtype.upper()] = vals

    def _load_file(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._load_dict(data)
                logger.debug(f"Loaded {len(self.records)} offline DNS fixture domains from {path}")
        except Exception as e:
            logger.error(f"Failed to load DNS fixtures from {path}: {e}")

    def add_record(self, domain: str, qtype: str, values: Union[List[str], str, List[Tuple[int, str]]]) -> None:
        """Dynamically register a record in the offline resolver."""
        norm_domain = self._normalize_name(domain)
        if norm_domain not in self.records:
            self.records[norm_domain] = {}
        if isinstance(values, str):
            values = [values]
        self.records[norm_domain][qtype.upper()] = values

    def query_txt(self, domain: str) -> List[str]:
        norm = self._normalize_name(domain)
        recs = self.records.get(norm, {})
        txt_recs = recs.get("TXT", [])
        if isinstance(txt_recs, list):
            return [str(r) for r in txt_recs]
        return [str(txt_recs)]

    def query_a(self, domain: str) -> List[str]:
        norm = self._normalize_name(domain)
        recs = self.records.get(norm, {})
        a_recs = recs.get("A", [])
        if isinstance(a_recs, list):
            return [str(r) for r in a_recs]
        return [str(a_recs)]

    def query_mx(self, domain: str) -> List[Tuple[int, str]]:
        norm = self._normalize_name(domain)
        recs = self.records.get(norm, {})
        mx_recs = recs.get("MX", [])
        results: List[Tuple[int, str]] = []
        for r in mx_recs:
            if isinstance(r, (list, tuple)) and len(r) == 2:
                results.append((int(r[0]), str(r[1])))
            elif isinstance(r, str):
                results.append((10, r))
        return results

    def spf_dns_lookup(self, name: str, qtype: str, tcpfallback: bool = True, timeout: int = 20) -> List[Any]:
        """Return pyspf-compatible response format: [((name, qtype), rdata_val)]."""
        norm = self._normalize_name(name)
        qtype_upper = qtype.upper()
        ret_val: List[Any] = []

        recs = self.records.get(norm, {})
        if qtype_upper in recs:
            raw_vals = recs[qtype_upper]
            if not isinstance(raw_vals, list):
                raw_vals = [raw_vals]

            for item in raw_vals:
                if qtype_upper in ("TXT", "SPF"):
                    # pyspf expects tuples of strings/bytes for rdata.strings
                    if isinstance(item, str):
                        ret_val.append(((name, qtype_upper), (item.encode("utf-8"),)))
                    elif isinstance(item, (list, tuple)):
                        encoded = tuple(v.encode("utf-8") if isinstance(v, str) else v for v in item)
                        ret_val.append(((name, qtype_upper), encoded))
                elif qtype_upper in ("A", "AAAA"):
                    ret_val.append(((name, qtype_upper), str(item)))
                elif qtype_upper == "MX":
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        ret_val.append(((name, qtype_upper), (item[0], item[1])))
                    else:
                        ret_val.append(((name, qtype_upper), (10, str(item))))
                elif qtype_upper == "PTR":
                    ret_val.append(((name, qtype_upper), str(item)))

        return ret_val

    def dkim_dns_lookup(self, name: Union[bytes, str], timeout: int = 5) -> bytes:
        """Return dkimpy-compatible raw TXT record bytestring."""
        if isinstance(name, bytes):
            try:
                domain = name.decode("utf-8")
            except Exception:
                domain = name.decode("latin1")
        else:
            domain = str(name)

        txts = self.query_txt(domain)
        if not txts:
            raise DNSNoAnswerError(f"No TXT record found offline for {domain}")
        # Return first DKIM TXT record encoded
        return txts[0].encode("utf-8")


class LiveDNSResolver(BaseDNSResolver):
    """Live DNS resolver utilizing dnspython with caching, timeouts, and fallback error handling."""

    def __init__(self, timeout: float = 3.0, retries: int = 2, cache_ttl: int = 300):
        self.timeout = timeout
        self.retries = retries
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, Tuple[float, Any]] = {}

        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def _get_from_cache(self, key: str) -> Optional[Any]:
        if key in self.cache:
            ts, val = self.cache[key]
            if time.time() - ts < self.cache_ttl:
                return val
            del self.cache[key]
        return None

    def _set_cache(self, key: str, val: Any) -> None:
        self.cache[key] = (time.time(), val)

    def query_txt(self, domain: str) -> List[str]:
        cache_key = f"TXT:{domain.lower()}"
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached

        results: List[str] = []
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_str = "".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                results.append(txt_str)
            self._set_cache(cache_key, results)
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self._set_cache(cache_key, [])
            return []
        except dns.exception.Timeout as e:
            raise DNSTimeoutError(f"DNS timeout querying TXT for {domain}: {e}") from e
        except Exception as e:
            raise DNSLookupError(f"DNS query failed for {domain} TXT: {e}") from e

    def query_a(self, domain: str) -> List[str]:
        cache_key = f"A:{domain.lower()}"
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached

        results: List[str] = []
        try:
            answers = self.resolver.resolve(domain, "A")
            for rdata in answers:
                results.append(rdata.address)
            self._set_cache(cache_key, results)
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self._set_cache(cache_key, [])
            return []
        except dns.exception.Timeout as e:
            raise DNSTimeoutError(f"DNS timeout querying A for {domain}: {e}") from e
        except Exception as e:
            raise DNSLookupError(f"DNS query failed for {domain} A: {e}") from e

    def query_mx(self, domain: str) -> List[Tuple[int, str]]:
        cache_key = f"MX:{domain.lower()}"
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached

        results: List[Tuple[int, str]] = []
        try:
            answers = self.resolver.resolve(domain, "MX")
            for rdata in answers:
                results.append((rdata.preference, str(rdata.exchange).rstrip(".")))
            self._set_cache(cache_key, results)
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self._set_cache(cache_key, [])
            return []
        except dns.exception.Timeout as e:
            raise DNSTimeoutError(f"DNS timeout querying MX for {domain}: {e}") from e
        except Exception as e:
            raise DNSLookupError(f"DNS query failed for {domain} MX: {e}") from e

    def spf_dns_lookup(self, name: str, qtype: str, tcpfallback: bool = True, timeout: int = 20) -> List[Any]:
        """Wrapper over dnspython lookup for pyspf."""
        import spf
        try:
            return spf.DNSLookup_dnspython(name, qtype, tcpfallback=tcpfallback, timeout=timeout)
        except Exception as e:
            logger.debug(f"spf_dns_lookup exception for {name} ({qtype}): {e}")
            return []

    def dkim_dns_lookup(self, name: Union[bytes, str], timeout: int = 5) -> bytes:
        """DKIM public key lookup using dkim.get_txt."""
        import dkim
        if isinstance(name, str):
            name_bytes = name.encode("utf-8")
        else:
            name_bytes = name
        return dkim.get_txt(name_bytes, timeout=timeout)


def get_resolver(
    offline: bool = False,
    fixtures_path: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> BaseDNSResolver:
    """Factory helper to obtain the appropriate DNS resolver instance."""
    if offline:
        path = fixtures_path
        if not path and config:
            path = config.get("dns", {}).get("fixtures_file")
        return OfflineDNSResolver(fixtures_path=path)

    timeout = 3.0
    retries = 2
    cache_ttl = 300
    if config and "dns" in config:
        dns_cfg = config["dns"]
        timeout = float(dns_cfg.get("timeout_seconds", 3.0))
        retries = int(dns_cfg.get("retries", 2))
        cache_ttl = int(dns_cfg.get("cache_ttl_seconds", 300))

    return LiveDNSResolver(timeout=timeout, retries=retries, cache_ttl=cache_ttl)
