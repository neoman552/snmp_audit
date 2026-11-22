#!/usr/bin/env python3
"""MC2S SNMP AUDIT — Outil défensif de diagnostic et d'audit SNMPv1/v2c."""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import logging
from pathlib import Path
import random
import socket
import time
from typing import Any

from pyasn1.codec.ber import encoder
from pyasn1.type import univ

LOGGER = logging.getLogger("mc2s_snmp_audit")

BANNER = r"""
  __  __  ____ ____  ____    ____  _   _ __  __ ____     _   _   _ ____ ___ _____
 |  \/  |/ ___|___ \/ ___|  / ___|| \ | |  \/  |  _ \   / \ | | | |  _ \_ _|_   _|
 | |\/| | |     __) \___ \  \___ \|  \| | |\/| | |_) | / _ \| | | | | | | |  | |
 | |  | | |___ / __/ ___) |  ___) | |\  | |  | |  __/ / ___ \ |_| | |_| | |  | |
 |_|  |_|\____|_____|____/  |____/|_| \_|_|  |_|_|   /_/   \_\___/|____/___| |_|
"""

DESCRIPTION = (
    "Audit défensif de configuration SNMPv1/v2c : vérification de communauté "
    "(unique ou wordlist), collecte d'informations système et évaluation des bonnes pratiques."
)

DEFAULT_WORDLIST = Path("wordlists/communities.txt")

DEFAULT_SCALAR_OIDS: list[tuple[str, str]] = [
    ("1.3.6.1.2.1.1.1.0", "sysDescr"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
    ("1.3.6.1.2.1.1.4.0", "sysContact"),
    ("1.3.6.1.2.1.1.5.0", "sysName"),
    ("1.3.6.1.2.1.1.6.0", "sysLocation"),
    ("1.3.6.1.2.1.2.1.0", "ifNumber"),
]

TABLE_OIDS: list[tuple[str, str]] = [
    ("1.3.6.1.2.1.2.2.1.2", "ifDescr"),
    ("1.3.6.1.2.1.4.20.1.1", "ipAdEntAddr"),
]

VENDOR_KEYWORDS: dict[str, str] = {
    "cisco": "Cisco",
    "juniper": "Juniper",
    "arista": "Arista",
    "hp": "HP / HPE",
    "hpe": "HP / HPE",
    "mikrotik": "MikroTik",
    "tp-link": "TP-Link",
    "eap": "TP-Link",
    "linux": "Linux",
}

PDU_GET_REQUEST = 0xA0
PDU_GET_NEXT_REQUEST = 0xA1


def print_banner() -> None:
    """Affiche la bannière MC2S SNMP AUDIT et le descriptif de l'outil."""
    print(BANNER)
    print(f"  {DESCRIPTION}\n")


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode un champ Tag-Length-Value BER."""
    length = len(value)
    if length < 0x80:
        len_bytes = bytes([length])
    else:
        raw_len = length.to_bytes((length.bit_length() + 7) // 8, "big")
        len_bytes = bytes([0x80 | len(raw_len)]) + raw_len
    return bytes([tag]) + len_bytes + value


def build_snmp_pdu(
    version_int: int,
    community: str,
    oid: str,
    pdu_tag: int,
    request_id: int,
) -> bytes:
    """Construit un message SNMPv1/v2c encodé en BER pour un OID."""
    varbind = univ.Sequence()
    varbind.setComponentByPosition(0, univ.ObjectIdentifier(oid))
    varbind.setComponentByPosition(1, univ.Null())

    varbind_list = univ.Sequence()
    varbind_list.setComponentByPosition(0, varbind)

    pdu = univ.Sequence()
    pdu.setComponentByPosition(0, univ.Integer(request_id))
    pdu.setComponentByPosition(1, univ.Integer(0))
    pdu.setComponentByPosition(2, univ.Integer(0))
    pdu.setComponentByPosition(3, varbind_list)

    pdu_bytes = encoder.encode(pdu)
    tagged_pdu = bytes([pdu_tag]) + pdu_bytes[1:]

    ver_bytes = encoder.encode(univ.Integer(version_int))
    comm_bytes = encoder.encode(univ.OctetString(community.encode("utf-8")))
    body = ver_bytes + comm_bytes + tagged_pdu
    return encode_tlv(0x30, body)


def _read_ber_length(buf: bytes, pos: int) -> tuple[int, int]:
    """Lit une longueur BER à partir de pos et retourne (longueur, nouvelle_pos)."""
    if pos >= len(buf):
        raise ValueError("Fin de paquet BER inattendue lors de la lecture de la longueur.")
    first = buf[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    num_octets = first & 0x7F
    if num_octets == 0 or pos + num_octets > len(buf):
        raise ValueError("Longueur BER multi-octets invalide.")
    length = int.from_bytes(buf[pos : pos + num_octets], "big")
    return length, pos + num_octets


def _decode_oid(raw: bytes) -> str:
    """Décode un OID BER brut en chaîne pointée."""
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _format_raw_snmp_value(tag: int, raw: bytes) -> str:
    """Formate une valeur BER brute selon son tag SNMP/ASN.1."""
    if tag == 0x05 or tag in (0x80, 0x81, 0x82):
        return ""
    if tag == 0x02:
        return str(int.from_bytes(raw, "big", signed=True)) if raw else "0"
    if tag == 0x06:
        return _decode_oid(raw)
    if tag == 0x40:
        return ".".join(str(b) for b in raw)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(raw, "big", signed=False)) if raw else "0"
    if tag == 0x04:
        try:
            text = raw.decode("utf-8")
            if text.isprintable():
                return text
        except UnicodeDecodeError:
            pass
        return raw.hex(":")
    return raw.hex(":")


def parse_snmp_response(data: bytes) -> tuple[str | None, str | None]:
    """Parse une réponse SNMPv1/v2c et retourne (oid, valeur_formatée)."""
    pos = 0
    if pos >= len(data) or data[pos] != 0x30:
        raise ValueError("Message SNMP invalide (tag SEQUENCE 0x30 attendu).")
    _, pos = _read_ber_length(data, pos + 1)

    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Champ version SNMP manquant.")
    v_len, pos = _read_ber_length(data, pos + 1)
    pos += v_len

    if pos >= len(data) or data[pos] != 0x04:
        raise ValueError("Champ community SNMP manquant.")
    c_len, pos = _read_ber_length(data, pos + 1)
    pos += c_len

    if pos >= len(data) or (data[pos] & 0xE0) != 0xA0:
        raise ValueError("PDU SNMP invalide.")
    _, pos = _read_ber_length(data, pos + 1)

    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Request-ID manquant.")
    r_len, pos = _read_ber_length(data, pos + 1)
    pos += r_len

    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Error-Status manquant.")
    e_len, pos = _read_ber_length(data, pos + 1)
    error_status = int.from_bytes(data[pos : pos + e_len], "big", signed=True) if e_len else 0
    pos += e_len

    if pos >= len(data) or data[pos] != 0x02:
        raise ValueError("Error-Index manquant.")
    ei_len, pos = _read_ber_length(data, pos + 1)
    pos += ei_len

    if error_status != 0:
        return None, None

    if pos >= len(data) or data[pos] != 0x30:
        return None, None
    _, pos = _read_ber_length(data, pos + 1)

    if pos >= len(data) or data[pos] != 0x30:
        return None, None
    _, pos = _read_ber_length(data, pos + 1)

    if pos >= len(data) or data[pos] != 0x06:
        return None, None
    oid_len, pos = _read_ber_length(data, pos + 1)
    oid_str = _decode_oid(data[pos : pos + oid_len])
    pos += oid_len

    if pos >= len(data):
        return oid_str, ""
    val_tag = data[pos]
    val_len, pos = _read_ber_length(data, pos + 1)
    val_raw = data[pos : pos + val_len]
    return oid_str, _format_raw_snmp_value(val_tag, val_raw)


def snmp_query(
    host: str,
    port: int,
    version: str,
    community: str,
    oid: str,
    pdu_tag: int,
    timeout: float,
    retries: int,
) -> tuple[str | None, str | None]:
    """Envoie une requête SNMP GET ou GETNEXT et retourne (oid_réponse, valeur)."""
    version_int = 0 if version == "v1" else 1
    req_id = random.randint(1000, 999999)
    packet = build_snmp_pdu(version_int, community, oid, pdu_tag, req_id)

    for attempt in range(retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (host, port))
                data, _ = sock.recvfrom(65535)

            if not data:
                return None, None

            return parse_snmp_response(data)

        except socket.timeout:
            LOGGER.debug("Timeout sur %s (essai %d/%d)", oid, attempt + 1, retries + 1)
        except Exception as exc:
            LOGGER.warning("Erreur requête SNMP sur %s: %s", oid, exc)
            break

    return None, None


def snmp_get_scalars(
    host: str,
    port: int,
    version: str,
    community: str,
    oids: list[tuple[str, str]],
    timeout: float,
    retries: int,
) -> dict[str, str]:
    """Récupère les valeurs scalaires associées aux OIDs fournis."""
    collected: dict[str, str] = {}
    for oid, label in oids:
        _, val = snmp_query(
            host=host,
            port=port,
            version=version,
            community=community,
            oid=oid,
            pdu_tag=PDU_GET_REQUEST,
            timeout=timeout,
            retries=retries,
        )
        if val is not None and val != "":
            collected[label] = val
    return collected


def snmp_walk_table(
    host: str,
    port: int,
    version: str,
    community: str,
    root_oid: str,
    timeout: float,
    retries: int,
    max_entries: int = 100,
) -> list[dict[str, str]]:
    """Parcourt une table SNMP via GETNEXT tant que l'OID reste sous root_oid."""
    entries: list[dict[str, str]] = []
    current_oid = root_oid
    prefix = root_oid.rstrip(".") + "."

    for _ in range(max_entries):
        next_oid, val = snmp_query(
            host=host,
            port=port,
            version=version,
            community=community,
            oid=current_oid,
            pdu_tag=PDU_GET_NEXT_REQUEST,
            timeout=timeout,
            retries=retries,
        )
        if not next_oid or not next_oid.startswith(prefix) or next_oid == current_oid:
            break
        entries.append({"oid": next_oid, "value": val or ""})
        current_oid = next_oid

    return entries


def load_wordlist(path: Path) -> list[str]:
    """Charge une liste de communautés depuis un fichier texte."""
    if not path.is_file():
        raise FileNotFoundError(f"Wordlist introuvable : {path}")
    communities: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        if candidate not in seen:
            seen.add(candidate)
            communities.append(candidate)
    return communities


def find_valid_community(
    host: str,
    port: int,
    version: str,
    candidates: list[str],
    timeout: float,
    retries: int,
    delay: float,
) -> str | None:
    """Teste une liste de communautés sur sysDescr.0 et retourne la première valide."""
    probe_oid = DEFAULT_SCALAR_OIDS[0][0]
    for idx, comm in enumerate(candidates, start=1):
        LOGGER.debug("Test communauté [%d/%d] : %s", idx, len(candidates), comm)
        _, val = snmp_query(
            host=host,
            port=port,
            version=version,
            community=comm,
            oid=probe_oid,
            pdu_tag=PDU_GET_REQUEST,
            timeout=timeout,
            retries=retries,
        )
        if val is not None and val != "":
            LOGGER.info("Communauté valide trouvée : '%s'", comm)
            return comm
        if delay > 0:
            time.sleep(delay)
    return None


def validate_target(target: str) -> str:
    """Valide une adresse IP ou résout un nom d'hôte."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        info = socket.getaddrinfo(target, None, family=socket.AF_INET)
        return info[0][4][0]


def detect_vendor(sysdescr: str) -> str:
    """Identifie le constructeur à partir de sysDescr."""
    lowered = sysdescr.lower()
    for token, vendor in VENDOR_KEYWORDS.items():
        if token in lowered:
            return vendor
    return "Inconnu"


def assess_posture(version: str, community: str, scalars: dict[str, str]) -> list[dict[str, str]]:
    """Évalue la posture SNMP et fournit des recommandations défensives."""
    findings: list[dict[str, str]] = []

    if scalars:
        findings.append(
            {
                "check": "Protocole SNMP non chiffré",
                "severity": "Élevé",
                "detail": f"L'agent répond en SNMP{version} sans chiffrement ni authentification cryptographique.",
                "remediation": "Migrer vers SNMPv3 en mode authPriv et filtrer l'accès par ACL.",
            }
        )
        if community in ("public", "private"):
            findings.append(
                {
                    "check": "Communauté SNMP par défaut",
                    "severity": "Élevé",
                    "detail": f"La communauté par défaut '{community}' est acceptée par la cible.",
                    "remediation": "Remplacer la communauté par défaut ou désactiver SNMPv1/v2c.",
                }
            )
    else:
        findings.append(
            {
                "check": "Aucune réponse SNMP",
                "severity": "Info",
                "detail": "Aucune réponse reçue pour les paramètres fournis (service inactif, pare-feu ou communauté différente).",
                "remediation": "Vérifier l'état du service SNMP, la connectivité UDP et la configuration de la cible.",
            }
        )

    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mc2s_snmp_audit",
        description=DESCRIPTION,
    )
    parser.add_argument("target", help="Adresse IP ou nom d'hôte cible")
    parser.add_argument("-p", "--port", type=int, default=161, help="Port UDP SNMP (défaut: 161)")
    parser.add_argument("--version", choices=["v1", "v2c"], default="v2c", help="Version SNMP (défaut: v2c)")
    parser.add_argument("-c", "--community", default="public", help="Communauté SNMP unique (défaut: public)")
    parser.add_argument(
        "-w",
        "--wordlist",
        nargs="?",
        const=str(DEFAULT_WORDLIST),
        default=None,
        help=f"Fichier wordlist de communautés (défaut si indiqué sans chemin : {DEFAULT_WORDLIST})",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Pause en secondes entre chaque test de communauté (défaut: 0.05)",
    )
    parser.add_argument("--timeout", type=float, default=1.5, help="Délai d'attente en secondes")
    parser.add_argument("--retries", type=int, default=1, help="Nombre de tentatives")
    parser.add_argument("-o", "--output", default="reports/snmp_audit_report.json", help="Fichier JSON de sortie")
    parser.add_argument("--verbose", action="store_true", help="Active les logs détaillés")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    print_banner()

    try:
        host = validate_target(args.target)
    except (ValueError, socket.gaierror) as exc:
        LOGGER.error("Cible invalide ou résolution impossible : %s", exc)
        return 1

    active_community: str | None = args.community
    tested_count = 1

    if args.wordlist:
        try:
            candidates = load_wordlist(Path(args.wordlist))
        except FileNotFoundError as exc:
            LOGGER.error("%s", exc)
            return 1
        tested_count = len(candidates)
        LOGGER.info(
            "Test de %d communauté(s) depuis %s sur %s (%s:%d) en %s",
            tested_count,
            args.wordlist,
            args.target,
            host,
            args.port,
            args.version,
        )
        active_community = find_valid_community(
            host=host,
            port=args.port,
            version=args.version,
            candidates=candidates,
            timeout=args.timeout,
            retries=args.retries,
            delay=args.delay,
        )
        if not active_community:
            LOGGER.warning("Aucune communauté valide trouvée dans %s", args.wordlist)
            active_community = args.community
    else:
        LOGGER.info("Audit SNMP de %s (%s:%d) en %s", args.target, host, args.port, args.version)

    scalars = snmp_get_scalars(
        host=host,
        port=args.port,
        version=args.version,
        community=active_community,
        oids=DEFAULT_SCALAR_OIDS,
        timeout=args.timeout,
        retries=args.retries,
    )

    tables: dict[str, list[dict[str, str]]] = {}
    if scalars:
        for oid, label in TABLE_OIDS:
            tables[label] = snmp_walk_table(
                host=host,
                port=args.port,
                version=args.version,
                community=active_community,
                root_oid=oid,
                timeout=args.timeout,
                retries=args.retries,
            )

    vendor = detect_vendor(scalars.get("sysDescr", ""))
    findings = assess_posture(args.version, active_community, scalars)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "tool": "MC2S SNMP AUDIT",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {"input": args.target, "resolved": host, "port": args.port},
        "snmp": {
            "version": args.version,
            "community_tested": active_community if scalars else None,
            "candidates_tested": tested_count,
            "vendor": vendor,
            "scalars": scalars,
            "tables": tables,
        },
        "findings": findings,
    }

    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    LOGGER.info("Rapport enregistré dans %s (%d observation(s))", output_path, len(findings))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur.")