from __future__ import annotations


TECH_ALIASES = {
    "apache httpd": ["apache", "httpd"],
    "nginx": ["nginx"],
    "openssh": ["openssh", "ssh"],
    "wordpress": ["wordpress", "wp"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "tomcat": ["tomcat"],
    "jenkins": ["jenkins"],
    "phpmyadmin": ["phpmyadmin", "pma"],
    "php": ["php"],
    "vsftpd": ["vsftpd"],
    "proftpd": ["proftpd"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgres", "postgresql"],
    "smb": ["smb", "samba"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch"],
    "kubernetes": ["k8s", "kubernetes"],
    "grafana": ["grafana"],
    "gitlab": ["gitlab"],
    "confluence": ["confluence"],
    "jira": ["jira"],
    "log4j": ["log4j", "log4shell"],
}


class TechMatcher:
    def __init__(self):
        self.aliases = TECH_ALIASES

    def keywords(self, product: str, version: str = "") -> list[str]:
        p = (product or "").lower().strip()
        if not p:
            return []
        out: list[str] = []
        for canonical, variants in self.aliases.items():
            if p == canonical or p in variants or any(v in p for v in variants):
                out.append(canonical)
                out.extend(variants)
        if p not in out:
            out.append(p)

        result: list[str] = []
        seen: set[str] = set()
        for k in out:
            for kw in (k, f"{k} {version}".strip() if version else ""):
                if kw and kw not in seen:
                    seen.add(kw)
                    result.append(kw)
        return result
