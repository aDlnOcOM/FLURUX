"""Supported compatibility profiles for the pinned Windows engine."""

from dataclasses import dataclass
from itertools import product

METHODS = {
    "split": "Разделение TLS",
    "disorder": "Перестановка TLS",
    "quic": "Разделение TLS + QUIC",
    "disorder_quic": "Перестановка TLS + QUIC",
}
FAMILIES = {"both": "IPv4 и IPv6", "ipv4": "IPv4", "ipv6": "IPv6"}
PORT_SETS = {
    "HTTPS · 443": "443",
    "HTTPS · 8443": "8443",
    "HTTPS · 9443": "9443",
    "HTTPS · 443, 8443": "443,8443",
    "HTTPS · 443, 8443, 9443": "443,8443,9443",
}
QUIC_METHODS = frozenset(("quic", "disorder_quic"))


@dataclass(frozen=True)
class Preset:
    """One combination of method, IP family and destination port coverage."""

    method: str
    family: str
    ports: str

    @property
    def label(self) -> str:
        """Return the complete configuration in a readable form."""
        return f"{METHODS[self.method]} · {FAMILIES[self.family]} · {self.ports}"


PRESETS = tuple(Preset(*selection) for selection in product(METHODS, FAMILIES, PORT_SETS.values()))
