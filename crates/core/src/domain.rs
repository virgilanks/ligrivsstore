//! Correspondance des domaines : quelles entrées proposer sur la page ouverte.
//!
//! Le navigateur donne l'adresse de la page (jamais la page elle-même) ; chaque
//! entrée a son adresse. Les règles (note de conception n° 3, section 6.4) :
//!
//! | Cas | Page / entrée | Résultat |
//! |---|---|---|
//! | Même origine | `https://www.banque.fr/connexion` / `https://www.banque.fr` | [`Proximity::SameOrigin`], proposée en premier |
//! | Même hôte, autre port ou schéma | `https://www.banque.fr:8443` / `https://www.banque.fr` | [`Proximity::SameHost`] |
//! | Autre sous-domaine du même domaine | `https://client.banque.fr` / `https://www.banque.fr` | [`Proximity::Subdomain`], avec une mention |
//! | Autre domaine, même ressemblant | `https://banque-fr.secure-login.com` / `https://www.banque.fr` | jamais |
//! | Suffixe public partagé | `https://alice.github.io` / `https://bob.github.io` | jamais |
//! | Adresse IP, `localhost`, nom sans domaine | `https://192.168.30.10:8006` / même adresse | hôte et port exacts seulement |
//! | Page en HTTP | `http://…` / entrée en `https://…` | jamais ; une entrée en `http://` est proposée, signalée non chiffrée |
//! | Entrée sans adresse, ou autre schéma | — | jamais |
//!
//! Le domaine enregistrable (par exemple `banque.fr`, `example.co.uk` ou
//! `alice.github.io`) vient de la liste des suffixes publics, compilée dans le
//! programme (paquet `psl`), parties ICANN et privée comprises. Les noms de
//! domaine internationalisés sont comparés sous leur forme ASCII (Punycode),
//! après normalisation par le paquet `url` : une lettre cyrillique qui imite
//! une lettre latine donne un autre domaine.

use url::{Host, Url};

/// Origine de la page ouverte, lue par le navigateur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageOrigin {
    secure: bool,
    host: String,
    port: u16,
    registrable: Option<String>,
}

/// Proximité entre la page et l'entrée, de la plus forte à la plus faible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proximity {
    /// Même schéma, même hôte et même port.
    SameOrigin,
    /// Même hôte, autre port ou autre schéma (entrée en `http://` sur une
    /// page en `https://`).
    SameHost,
    /// Autre sous-domaine du même domaine enregistrable : à signaler.
    Subdomain,
}

/// Une entrée qui correspond à la page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteMatch {
    /// Proximité, pour classer et signaler.
    pub proximity: Proximity,
    /// Page en `http://` : l'identifiant partirait sans chiffrement.
    pub insecure: bool,
}

/// Hôte normalisé d'une adresse en `http://` ou `https://`.
struct Address {
    secure: bool,
    host: String,
    port: u16,
    registrable: Option<String>,
}

impl PageOrigin {
    /// Lit l'adresse de la page. `None` pour tout ce qui n'est pas une page
    /// Web en `http://` ou `https://` (pages internes du navigateur,
    /// `file:`, `data:`…) : rien n'y est proposé.
    pub fn parse(page_url: &str) -> Option<Self> {
        let url = Url::parse(page_url.trim()).ok()?;
        let address = Address::from_url(&url)?;
        Some(Self {
            secure: address.secure,
            host: address.host,
            port: address.port,
            registrable: address.registrable,
        })
    }

    /// Hôte de la page, sous sa forme ASCII.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Compare la page à l'adresse d'une entrée.
    pub fn matches(&self, entry_url: &str) -> Option<SiteMatch> {
        let entry = Address::from_entry(entry_url)?;
        // Une page en http:// ne reçoit que des entrées en http://, signalées.
        if !self.secure && entry.secure {
            return None;
        }
        let insecure = !self.secure;
        let proximity = if entry.host == self.host {
            if entry.port == self.port && entry.secure == self.secure {
                Proximity::SameOrigin
            } else if self.registrable.is_none() {
                // Adresse IP, localhost, nom sans domaine : port exact exigé.
                if entry.port == self.port {
                    Proximity::SameHost
                } else {
                    return None;
                }
            } else {
                Proximity::SameHost
            }
        } else {
            match (&self.registrable, &entry.registrable) {
                (Some(page), Some(entry)) if page == entry => Proximity::Subdomain,
                _ => return None,
            }
        };
        Some(SiteMatch {
            proximity,
            insecure,
        })
    }
}

impl Address {
    /// Adresse d'une entrée : le schéma manquant vaut `https://`
    /// (`www.banque.fr`, `banque.fr/connexion`).
    fn from_entry(entry_url: &str) -> Option<Self> {
        let text = entry_url.trim();
        if text.is_empty() {
            return None;
        }
        let url = if text.contains("://") {
            Url::parse(text).ok()?
        } else {
            Url::parse(&format!("https://{text}")).ok()?
        };
        Self::from_url(&url)
    }

    fn from_url(url: &Url) -> Option<Self> {
        let secure = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let port = url.port_or_known_default()?;
        let (host, registrable) = match url.host()? {
            Host::Domain(domain) => {
                let host = domain.trim_end_matches('.').to_ascii_lowercase();
                if host.is_empty() {
                    return None;
                }
                let registrable = registrable_domain(&host);
                (host, registrable)
            }
            Host::Ipv4(address) => (address.to_string(), None),
            Host::Ipv6(address) => (address.to_string(), None),
        };
        Some(Self {
            secure,
            host,
            port,
            registrable,
        })
    }
}

/// Domaine enregistrable d'un hôte, `None` pour `localhost`, un nom sans
/// point, ou un hôte qui est lui-même un suffixe public (`github.io`).
fn registrable_domain(host: &str) -> Option<String> {
    if host == "localhost" || host.ends_with(".localhost") || !host.contains('.') {
        return None;
    }
    psl::domain_str(host).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(page: &str, entry: &str) -> Option<SiteMatch> {
        PageOrigin::parse(page)
            .unwrap_or_else(|| panic!("page illisible : {page}"))
            .matches(entry)
    }

    fn proximity(page: &str, entry: &str) -> Option<Proximity> {
        check(page, entry).map(|m| m.proximity)
    }

    #[test]
    fn cases_of_the_design_note() {
        use Proximity::*;
        let cases: &[(&str, &str, Option<Proximity>)] = &[
            // Même origine, proposée en premier.
            (
                "https://www.banque.fr/connexion",
                "https://www.banque.fr",
                Some(SameOrigin),
            ),
            // Même hôte, autre chemin ou port.
            (
                "https://www.banque.fr:8443/x",
                "https://www.banque.fr",
                Some(SameHost),
            ),
            (
                "https://www.banque.fr/",
                "https://www.banque.fr:8443/",
                Some(SameHost),
            ),
            // Autre sous-domaine du même domaine : proposée, signalée.
            (
                "https://client.banque.fr",
                "https://www.banque.fr",
                Some(Subdomain),
            ),
            (
                "https://banque.fr",
                "https://www.banque.fr",
                Some(Subdomain),
            ),
            // Autre domaine, même ressemblant : jamais.
            (
                "https://banque-fr.secure-login.com",
                "https://www.banque.fr",
                None,
            ),
            (
                "https://www.banque.fr.secure-login.com",
                "https://www.banque.fr",
                None,
            ),
            ("https://banquefr.com", "https://www.banque.fr", None),
            // Suffixe public partagé (partie privée de la liste) : jamais.
            ("https://alice.github.io", "https://bob.github.io", None),
            (
                "https://alice.github.io/depot",
                "https://alice.github.io",
                Some(SameOrigin),
            ),
            ("https://github.io", "https://alice.github.io", None),
            // Adresses IP et localhost : hôte et port exacts seulement.
            (
                "https://192.168.30.10:8006",
                "https://192.168.30.10:8006",
                Some(SameOrigin),
            ),
            ("https://192.168.30.10:8006", "https://192.168.30.10", None),
            (
                "https://192.168.30.10:8006",
                "https://192.168.30.11:8006",
                None,
            ),
            (
                "http://localhost:8080",
                "http://localhost:8080/login",
                Some(SameOrigin),
            ),
            ("http://localhost:8080", "http://localhost:3000", None),
            ("https://[::1]:8443", "https://[::1]:8443", Some(SameOrigin)),
            // Nom sans domaine (réseau local) : exact.
            ("https://nas:5001", "https://nas:5001", Some(SameOrigin)),
            ("https://nas:5001", "https://nas2:5001", None),
            // Page en HTTP : jamais d'entrée en https://.
            ("http://www.banque.fr", "https://www.banque.fr", None),
            (
                "http://www.banque.fr",
                "http://www.banque.fr",
                Some(SameOrigin),
            ),
            // Entrée en http:// sur une page en https:// : même hôte.
            (
                "https://www.banque.fr",
                "http://www.banque.fr",
                Some(SameHost),
            ),
            // Entrée sans adresse, ou dans un autre schéma : jamais.
            ("https://www.banque.fr", "", None),
            ("https://www.banque.fr", "   ", None),
            ("https://www.banque.fr", "ssh://www.banque.fr", None),
            ("https://www.banque.fr", "androidapp://fr.banque.app", None),
            ("https://www.banque.fr", "ftp://www.banque.fr", None),
        ];
        for (page, entry, expected) in cases {
            assert_eq!(
                &proximity(page, entry),
                expected,
                "page {page}, entrée {entry}"
            );
        }
    }

    #[test]
    fn an_entry_without_scheme_is_read_as_https() {
        assert_eq!(
            proximity("https://www.banque.fr", "www.banque.fr"),
            Some(Proximity::SameOrigin)
        );
        assert_eq!(
            proximity("https://www.banque.fr", "banque.fr/connexion"),
            Some(Proximity::Subdomain)
        );
        assert_eq!(
            proximity("https://192.168.30.10:8006", "192.168.30.10:8006"),
            Some(Proximity::SameOrigin)
        );
        // Lu en https://, donc jamais sur une page en http://.
        assert_eq!(proximity("http://www.banque.fr", "www.banque.fr"), None);
    }

    #[test]
    fn a_page_in_http_is_flagged_insecure() {
        let found = check("http://intranet.exemple.fr", "http://intranet.exemple.fr").unwrap();
        assert!(found.insecure);
        let found = check("https://www.banque.fr", "http://www.banque.fr").unwrap();
        assert!(!found.insecure, "page chiffrée : rien ne part en clair");
    }

    #[test]
    fn country_and_multi_label_suffixes() {
        use Proximity::*;
        let cases: &[(&str, &str, Option<Proximity>)] = &[
            (
                "https://www.example.co.uk",
                "https://login.example.co.uk",
                Some(Subdomain),
            ),
            ("https://example.co.uk", "https://other.co.uk", None),
            ("https://compte.impots.gouv.fr", "https://www.gouv.fr", None),
            ("https://a.blogspot.com", "https://b.blogspot.com", None),
            (
                "https://www.amazon.com",
                "https://amazon.com",
                Some(Subdomain),
            ),
            ("https://www.amazon.com", "https://www.amazon.fr", None),
        ];
        for (page, entry, expected) in cases {
            assert_eq!(
                &proximity(page, entry),
                expected,
                "page {page}, entrée {entry}"
            );
        }
    }

    #[test]
    fn lookalike_and_internationalised_names_never_match() {
        // « раураl » en lettres cyrilliques : un autre domaine.
        assert_eq!(proximity("https://раураl.com", "https://paypal.com"), None);
        assert_eq!(proximity("https://paypal.com", "https://раураl.com"), None);
        // Le même nom, écrit en Unicode ou en Punycode, se reconnaît.
        assert_eq!(
            proximity("https://www.société.fr", "https://www.xn--socit-esab.fr"),
            Some(Proximity::SameOrigin)
        );
        assert_eq!(
            proximity("https://client.société.fr", "https://www.société.fr"),
            Some(Proximity::Subdomain)
        );
        // Suffixe internationalisé (.рф).
        assert_eq!(
            proximity("https://www.пример.рф", "https://login.пример.рф"),
            Some(Proximity::Subdomain)
        );
        assert_eq!(
            proximity("https://www.пример.рф", "https://www.другой.рф"),
            None
        );
    }

    #[test]
    fn spelling_variants_are_normalised() {
        use Proximity::*;
        let cases: &[(&str, &str, Option<Proximity>)] = &[
            (
                "https://WWW.Banque.FR/Connexion",
                "https://www.banque.fr",
                Some(SameOrigin),
            ),
            (
                "https://www.banque.fr./",
                "https://www.banque.fr",
                Some(SameOrigin),
            ),
            (
                "https://www.banque.fr:443/",
                "https://www.banque.fr",
                Some(SameOrigin),
            ),
            (
                "https://www.banque.fr",
                "https://hermann:secret@www.banque.fr/x?y#z",
                Some(SameOrigin),
            ),
            (
                "http://0x7f.1:8080",
                "http://127.0.0.1:8080",
                Some(SameOrigin),
            ),
            (
                "https://www.banque.fr",
                "  https://www.banque.fr  ",
                Some(SameOrigin),
            ),
        ];
        for (page, entry, expected) in cases {
            assert_eq!(
                &proximity(page, entry),
                expected,
                "page {page}, entrée {entry}"
            );
        }
    }

    #[test]
    fn browser_pages_and_garbage_are_not_pages() {
        for page in [
            "chrome://settings",
            "edge://settings",
            "chrome-extension://abcdefghijklmnop/popup.html",
            "about:blank",
            "file:///C:/Users/hermann/page.html",
            "data:text/html,<p>",
            "javascript:alert(1)",
            "pas une adresse",
            "",
            "https://",
        ] {
            assert_eq!(PageOrigin::parse(page), None, "{page}");
        }
        let page = PageOrigin::parse("https://www.banque.fr").unwrap();
        for entry in [
            "https://",
            "https:///chemin",
            "://www.banque.fr",
            "https://.",
            "http://[::1",
        ] {
            assert_eq!(page.matches(entry), None, "{entry}");
        }
    }

    #[test]
    fn proximity_orders_from_closest() {
        assert!(Proximity::SameOrigin < Proximity::SameHost);
        assert!(Proximity::SameHost < Proximity::Subdomain);
    }
}
