from route_manager.profiles import ENDPOINT_TYPES, Obj, port, source_network


def authority(name: str, number: int) -> str:
    """Format an IPv4, DNS or IPv6 socket address."""
    return f"[{name}]:{number}" if ":" in name else f"{name}:{number}"


def tls(n: Obj, *, server: bool = False) -> Obj:
    """Use the public PKI or the certificate synchronized over SSH."""
    if server:
        return {"enabled": True, "certificate_path": "cert.pem", "key_path": "key.pem"}
    result: Obj = {"enabled": True, "server_name": n["tls_name"] or n["host"]}
    if n["certificate"]:
        result["certificate"] = n["certificate"]
    return result


def auth(n: Obj) -> Obj:
    """Represent native proxy authentication."""
    return {"username": n["username"], "password": n["password"]} if n["password"] else {}


def wg(n: Obj, index: int, *, server: bool = False, peer_key: str = "") -> Obj:
    """Build a userspace endpoint with a distinct address space for each leg."""
    key = peer_key if server else n["public_key"]
    private = "@WG_PRIVATE@" if server else n["client_private"]
    if not key or not private:
        raise ValueError("Укажите ключи WireGuard или синхронизируйте собственные узлы.")
    peer: Obj = {
        "public_key": key,
        "allowed_ips": [f"10.231.{index}.2/32"] if server else ["0.0.0.0/0", "::/0"],
    }
    if not server:
        peer.update(address=n["host"], port=port(n["port"]), persistent_keepalive_interval=25)
    return {
        "type": "wireguard",
        "tag": f"wg{index}",
        "system": False,
        "mtu": 1340 if index == 0 else 1280,
        "address": [f"10.231.{index}.{1 if server else 2}/32"],
        "private_key": private,
        "peers": [peer],
        **({"listen_port": port(n["port"])} if server else {}),
    }


def outbound(n: Obj, index: int) -> Obj:
    """Translate one profile leg into a protocol endpoint or outbound."""
    kind = n["type"]
    if kind == "wg":
        return wg(n, index)
    base: Obj = {"tag": f"hop{index}", "server": n["host"], "server_port": port(n["port"])}
    if kind in ("http", "https", "socks"):
        return {
            **base,
            "type": "http" if kind == "https" else kind,
            **auth(n),
            **({"tls": tls(n)} if kind == "https" else {}),
        }
    if kind == "ss":
        return {
            **base,
            "type": "shadowsocks",
            "method": "chacha20-ietf-poly1305",
            "password": n["password"],
        }
    if kind == "hy2":
        return {**base, "type": "hysteria2", "password": n["password"], "tls": tls(n)}
    if kind == "masque_ip":
        return {
            **base,
            "type": "masque-client",
            "version": 3,
            "disable_version_fallback": True,
            **auth(n),
            "tls": tls(n),
        }
    if kind == "openvpn":
        trust = tls(n)
        trust.pop("enabled")
        return {**base, "type": "openvpn-client", "network": "tcp", **auth(n), "tls": trust}
    if kind == "reality":
        return {
            **base,
            "type": "vless",
            "uuid": n["password"],
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": n["tls_name"] or n["host"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": n["public_key"], "short_id": "34af"},
            },
        }
    raise ValueError("У этого профиля другой клиентский движок.")


def listener(p: Obj) -> Obj:
    """Bind application proxy traffic to loopback, or explicitly select a system TUN."""
    if p["system_tun"]:
        return {
            "type": "tun",
            "interface_name": "FLURUX-" + p["id"][:12],
            "tag": "local",
            "address": ["172.29.248.1/30", "fd74:260b:cd28::1/126"],
            "auto_route": True,
            "strict_route": True,
            "mtu": 1280,
        }
    return {
        "type": "mixed",
        "tag": "local",
        "listen": "127.0.0.1",
        "listen_port": port(p["local_port"]),
    }


def config(
    ins: list[Obj], outs: list[Obj], eps: list[Obj], final: str, rules: list[Obj] | None = None
) -> Obj:
    """Compile an explicit final route without an automatic direct fallback."""
    return {
        "dns": {"servers": [{"type": "local", "tag": "local-dns"}]},
        "inbounds": ins,
        "outbounds": outs,
        "endpoints": eps,
        "route": {
            "auto_detect_interface": any(i["type"] == "tun" for i in ins),
            "default_domain_resolver": "local-dns",
            "rules": rules or [],
            "final": final,
        },
    }


def fixed(network: str, address: str, number: int, target: str, target_port: int) -> Obj:
    """Forward a single port to one fixed destination."""
    incoming = {
        "type": "direct",
        "tag": "fixed",
        "listen": address,
        "listen_port": number,
        "network": network,
    }
    rule = {
        "inbound": ["fixed"],
        "action": "route",
        "outbound": "direct",
        "override_address": target,
        "override_port": target_port,
    }
    return config([incoming], [{"type": "direct", "tag": "direct"}], [], "direct", [rule])


def bootstrap_dns() -> Obj:
    """Resolve transport endpoints over authenticated HTTPS to a literal IP."""
    return {
        "type": "https",
        "tag": "bootstrap",
        "server": "1.1.1.1",
        "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
    }


def client(p: Obj) -> Obj:
    """Build the active client topology."""
    nodes = p["nodes"]
    if p["kind"] in ("dns_https", "dns_tls"):
        n = nodes[0]
        resolver = {
            "type": "https" if n["type"] == "doh" else "tls",
            "tag": "secure",
            "server": n["host"],
            "server_port": port(n["port"]),
            "tls": tls(n),
            "domain_resolver": "bootstrap",
        }
        return {
            "dns": {
                "servers": [resolver, bootstrap_dns()],
                "final": "secure",
            },
            "inbounds": [
                {
                    "type": "direct",
                    "tag": "dns-in",
                    "listen": "127.0.0.1",
                    "listen_port": port(p["local_port"]),
                }
            ],
            "route": {
                "default_domain_resolver": "bootstrap",
                "rules": [{"inbound": ["dns-in"], "action": "hijack-dns"}],
            },
        }
    if p["kind"].startswith("relay_"):
        result = fixed(
            p["kind"][6:],
            "127.0.0.1",
            port(p["local_port"]),
            nodes[0]["host"],
            port(nodes[0]["port"]),
        )
        result["dns"] = {"servers": [bootstrap_dns()], "final": "bootstrap"}
        result["route"]["default_domain_resolver"] = "bootstrap"
        return result
    hops = nodes[:1] if p["kind"] == "forwarded" else nodes
    outs: list[Obj] = []
    endpoints: list[Obj] = []
    previous = ""
    for index, n in enumerate(hops):
        leg = outbound(n, index)
        if previous:
            leg["detour"] = previous
        previous = leg["tag"]
        (endpoints if n["type"] in ENDPOINT_TYPES else outs).append(leg)
    rules = [{"port": 53, "action": "hijack-dns"}] if p["system_tun"] else []
    result = config([listener(p)], outs, endpoints, previous, rules)
    result["dns"] = {
        "servers": [bootstrap_dns(), dict(bootstrap_dns(), tag="tunnel-dns", detour=previous)],
        "final": "tunnel-dns",
    }
    result["route"]["default_domain_resolver"] = "bootstrap"
    return result


def server(p: Obj, index: int) -> Obj:
    """Build one user's server role, including the inter-server VPN leg."""
    n = p["nodes"][index]
    kind = n["type"]
    if kind.startswith("relay_"):
        cidr = source_network(p.get("access_cidr", ""))
        result = fixed(
            kind[6:],
            "::" if ":" in cidr else "0.0.0.0",
            port(n["port"]),
            p["target_host"],
            port(p["target_port"]),
        )
        rules = result["route"]["rules"]
        rules[0]["source_ip_cidr"] = [cidr]
        rules.append({"inbound": ["fixed"], "action": "reject"})
        return result
    tag = "incoming"
    base: Obj = {"tag": tag, "listen": "::", "listen_port": port(n["port"])}
    eps: list[Obj] = []
    ins: list[Obj] = []
    outs: list[Obj] = [{"type": "direct", "tag": "internet"}]
    final = "internet"
    if kind == "wg":
        peer = (
            p["nodes"][0].get("uplink_public", "")
            if p["kind"] == "forwarded" and index == 1
            else n["client_public"]
        )
        if not peer:
            raise ValueError(
                "Нужен отдельный публичный ключ связи шлюз–выход. Повторите настройку входного узла."
            )
        eps.append(wg(n, index, server=True, peer_key=peer))
        if p["kind"] == "forwarded" and index == 0:
            upstream = dict(p["nodes"][1], client_private="@WG_UPLINK@")
            link = wg(upstream, 1)
            eps.append(link)
            final = link["tag"]
            # Only decrypted client traffic may enter the second tunnel.
            return config(
                [],
                outs,
                eps,
                "internet",
                [{"inbound": ["wg0"], "action": "route", "outbound": final}],
            )
    elif kind in {"http", "socks", "https"}:
        ins.append(
            {
                **base,
                "type": "http" if kind == "https" else kind,
                "users": [auth(n)],
                **({"tls": tls(n, server=True)} if kind == "https" else {}),
            }
        )
    elif kind == "ss":
        ins.append(
            {
                **base,
                "type": "shadowsocks",
                "method": "chacha20-ietf-poly1305",
                "password": n["password"],
            }
        )
    elif kind == "hy2":
        ins.append(
            {
                **base,
                "type": "hysteria2",
                "users": [{"name": n["username"], "password": n["password"]}],
                "tls": tls(n, server=True),
            }
        )
    elif kind == "openvpn":
        eps.append(
            {
                **base,
                "type": "openvpn-server",
                "network": "tcp",
                "address": ["10.232.1.1/24"],
                "users": [auth(n)],
                "tls": {
                    "certificate_path": "cert.pem",
                    "key_path": "key.pem",
                    "verify_client_certificate": "none",
                },
            }
        )
    elif kind == "masque_ip":
        eps.append(
            {
                **base,
                "type": "masque-server",
                "version": [3],
                "users": [auth(n)],
                "address": ["10.232.2.1/24"],
                "advertise_routes": ["0.0.0.0/0", "::/0"],
                "tls": tls(n, server=True),
            }
        )
    elif kind == "reality":
        if not n["tls_name"]:
            raise ValueError("Для REALITY укажите имя доступного TLS-сайта в поле TLS/SNI.")
        ins.append(
            {
                **base,
                "type": "vless",
                "users": [{"uuid": n["password"], "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True,
                    "server_name": n["tls_name"],
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": n["tls_name"], "server_port": 443},
                        "private_key": "@REALITY_PRIVATE@",
                        "short_id": ["34af"],
                    },
                },
            }
        )
    else:
        raise ValueError("Для этого протокола используется отдельная серверная служба.")
    return config(ins, outs, eps, final)


def xray_ws(p: Obj, *, serving: bool = False) -> Obj:
    """Build a paired Xray Shadowsocks stream over WSS."""
    n = p["nodes"][0]
    stream: Obj = {"network": "ws", "security": "tls", "wsSettings": {"path": "/routes-stream"}}
    ss: Obj = {"method": "chacha20-ietf-poly1305", "password": n["password"]}
    if serving:
        stream["tlsSettings"] = {
            "certificates": [{"certificateFile": "cert.pem", "keyFile": "key.pem"}]
        }
        return {
            "inbounds": [
                {
                    "listen": "0.0.0.0",
                    "port": port(n["port"]),
                    "protocol": "shadowsocks",
                    "settings": {**ss, "network": "tcp"},
                    "streamSettings": stream,
                }
            ],
            "outbounds": [{"protocol": "freedom"}],
        }
    trust: Obj = {"serverName": n["tls_name"] or n["host"]}
    if n["certificate"]:
        trust["certificates"] = [{"usage": "verify", "certificate": n["certificate"].splitlines()}]
    stream["tlsSettings"] = trust
    return {
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port(p["local_port"]),
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "protocol": "shadowsocks",
                "settings": {"servers": [{**ss, "address": n["host"], "port": port(n["port"])}]},
                "streamSettings": stream,
            }
        ],
    }


def capsule(p: Obj) -> Obj:
    """Describe the TLS connection and its single UDP destination."""
    n = p["nodes"][0]
    return {
        "host": n["host"],
        "port": port(n["port"]),
        "name": n["tls_name"] or n["host"],
        "user": n["username"],
        "password": n["password"],
        "certificate": n["certificate"],
        "target": p["target_host"],
        "target_port": port(p["target_port"]),
        "local_port": port(p["local_port"]),
    }
