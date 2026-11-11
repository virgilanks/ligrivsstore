//! `lgs` : outil de développement et de recette du noyau ligrivsstore.
//!
//! Ce n'est pas l'application : il sert aux tests, à la recette et au
//! diagnostic. Les secrets ne passent jamais par la ligne de commande (visible
//! des autres processus) :
//! - phrase de passe du coffre : variable `LGS_PASSWORD` ;
//! - mot de passe WebDAV : variable `LGS_WEBDAV_PASSWORD` ;
//! - mot de passe d'une entrée : variable `LGS_ENTRY_PASSWORD`, ou `--generate`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use ligrivsstore_core::generator::{PasswordPolicy, generate_password};
use ligrivsstore_core::{
    EntryInput, Error, KdfParams, LocalVault, OpenLimits, SyncOptions, VaultKey, WebDavTransport,
    header, keyfile, storage,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "lgs",
    version,
    about = "Outil de développement et de recette du noyau ligrivsstore",
    after_help = "Secrets : LGS_PASSWORD (coffre), LGS_WEBDAV_PASSWORD (serveur), LGS_ENTRY_PASSWORD (entrée)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct VaultArgs {
    /// Fichier du coffre.
    file: PathBuf,
    /// Fichier clé, en plus de la phrase de passe.
    #[arg(long, short = 'k')]
    keyfile: Option<PathBuf>,
}

#[derive(Args)]
struct ServerArgs {
    /// Adresse du coffre sur le serveur, à la racine du dossier du compte
    /// (https://coffre.ligrivs.com/dav/<compte>/<coffre>.kdbx).
    #[arg(long)]
    url: String,
    /// Compte WebDAV.
    #[arg(long)]
    user: String,
    /// Autorité de certification (PEM) à reconnaître à la place des autorités
    /// publiques : banc d'essai ou serveur doté d'une autorité privée.
    #[arg(long)]
    ca_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Crée un coffre.
    New {
        #[command(flatten)]
        vault: VaultArgs,
        /// Nom du coffre.
        #[arg(long, default_value = "Coffre")]
        name: String,
        /// Nombre d'itérations d'Argon2id (sinon : valeur par défaut).
        #[arg(long, conflicts_with = "calibrate_ms")]
        iterations: Option<u64>,
        /// Calibre les itérations pour cette durée d'ouverture, en millisecondes.
        #[arg(long)]
        calibrate_ms: Option<u64>,
    },
    /// Ajoute une entrée.
    Add {
        #[command(flatten)]
        vault: VaultArgs,
        /// Titre.
        #[arg(long)]
        title: String,
        /// Adresse du site, serveur ou application.
        #[arg(long, default_value = "")]
        url: String,
        /// Identifiant ou adresse e-mail.
        #[arg(long, default_value = "")]
        username: String,
        /// Notes.
        #[arg(long, default_value = "")]
        notes: String,
        /// Génère un mot de passe de cette longueur (sinon : LGS_ENTRY_PASSWORD).
        #[arg(long)]
        generate: Option<usize>,
    },
    /// Liste les entrées, sans les mots de passe.
    List {
        #[command(flatten)]
        vault: VaultArgs,
    },
    /// Affiche une entrée.
    Show {
        #[command(flatten)]
        vault: VaultArgs,
        /// Titre de l'entrée.
        title: String,
        /// Affiche le mot de passe en clair.
        #[arg(long)]
        reveal: bool,
    },
    /// Modifie une entrée (l'ancienne version rejoint l'historique).
    Edit {
        #[command(flatten)]
        vault: VaultArgs,
        /// Titre de l'entrée.
        title: String,
        /// Nouvelle adresse.
        #[arg(long)]
        url: Option<String>,
        /// Nouvel identifiant.
        #[arg(long)]
        username: Option<String>,
        /// Nouvelles notes.
        #[arg(long)]
        notes: Option<String>,
        /// Nouveau mot de passe généré de cette longueur.
        #[arg(long, conflicts_with = "password_from_env")]
        generate: Option<usize>,
        /// Nouveau mot de passe lu dans LGS_ENTRY_PASSWORD.
        #[arg(long)]
        password_from_env: bool,
    },
    /// Supprime une entrée.
    Remove {
        #[command(flatten)]
        vault: VaultArgs,
        /// Titre de l'entrée.
        title: String,
    },
    /// Fusionne dans ce coffre un autre fichier du même coffre.
    Merge {
        #[command(flatten)]
        vault: VaultArgs,
        /// Autre version du coffre.
        other: PathBuf,
    },
    /// Synchronise avec le serveur « coffre ».
    Sync {
        #[command(flatten)]
        vault: VaultArgs,
        #[command(flatten)]
        server: ServerArgs,
        /// Lève la suspension qui suit un refus d'identifiants (après une
        /// nouvelle saisie du mot de passe WebDAV).
        #[arg(long)]
        new_credentials: bool,
    },
    /// Installe sur ce poste le coffre présent sur le serveur.
    Clone {
        #[command(flatten)]
        vault: VaultArgs,
        #[command(flatten)]
        server: ServerArgs,
    },
    /// Crée un fichier clé au format XML 2.0 de KeePass (celui de KeePassXC).
    Keyfile {
        /// Fichier à créer ; un fichier existant n'est jamais remplacé.
        path: PathBuf,
    },
    /// Affiche l'en-tête d'un coffre (format, chiffrement, dérivation), sans clé.
    Info {
        /// Fichier du coffre.
        file: PathBuf,
    },
    /// Liste les sauvegardes locales.
    Backups {
        #[command(flatten)]
        vault: VaultArgs,
    },
    /// Génère un mot de passe.
    Generate {
        /// Longueur.
        #[arg(long, default_value_t = 20)]
        length: usize,
        /// Sans symboles.
        #[arg(long)]
        no_symbols: bool,
        /// Sans chiffres.
        #[arg(long)]
        no_digits: bool,
        /// Sans majuscules.
        #[arg(long)]
        no_uppercase: bool,
        /// Sans minuscules.
        #[arg(long)]
        no_lowercase: bool,
        /// Sans caractères faciles à confondre.
        #[arg(long)]
        exclude_ambiguous: bool,
    },
    /// Mesure le nombre d'itérations d'Argon2id pour une durée d'ouverture.
    Calibrate {
        /// Durée visée, en millisecondes.
        #[arg(long, default_value_t = 1000)]
        target_ms: u64,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("erreur : {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::New {
            vault,
            name,
            iterations,
            calibrate_ms,
        } => {
            let kdf = match (iterations, calibrate_ms) {
                (Some(iterations), _) => KdfParams {
                    iterations,
                    ..KdfParams::default()
                },
                (None, Some(ms)) => KdfParams::calibrate(Duration::from_millis(ms))?,
                (None, None) => KdfParams::default(),
            };
            let local = LocalVault::create(&vault.file, &name, vault_key(&vault)?, kdf)?;
            println!("coffre créé : {}", local.path().display());
            if let Some(kdf) = local.vault().kdf() {
                println!("dérivation : {kdf}");
            }
        }
        Command::Add {
            vault,
            title,
            url,
            username,
            notes,
            generate,
        } => {
            let mut local = open(&vault)?;
            let password = match generate {
                Some(length) => generated(length)?,
                None => entry_password_from_env()?,
            };
            let id = local.vault_mut().add_entry(&EntryInput {
                title,
                url,
                username,
                password,
                notes,
            })?;
            local.save()?;
            println!("entrée ajoutée : {id}");
        }
        Command::List { vault } => {
            let local = open(&vault)?;
            let entries = local.vault().entries();
            if entries.is_empty() {
                eprintln!("aucune entrée dans ce coffre");
            }
            for entry in entries {
                println!("{}\t{}\t{}", entry.title, entry.username, entry.url);
            }
        }
        Command::Show {
            vault,
            title,
            reveal,
        } => {
            let local = open(&vault)?;
            let id = find(&local, &title)?;
            let entry = local.vault().entry(&id)?;
            println!("Titre : {}", entry.title);
            println!("Adresse : {}", entry.url);
            println!("Identifiant : {}", entry.username);
            if reveal {
                println!("Mot de passe : {}", entry.password.as_str());
            } else {
                println!("Mot de passe : ******** (--reveal pour l'afficher)");
            }
            println!("Notes : {}", entry.notes);
            println!("Modifiée : {}", entry.modified.as_deref().unwrap_or("-"));
            println!("Versions antérieures : {}", entry.history_len);
        }
        Command::Edit {
            vault,
            title,
            url,
            username,
            notes,
            generate,
            password_from_env,
        } => {
            let mut local = open(&vault)?;
            let id = find(&local, &title)?;
            let current = local.vault().entry(&id)?;
            let password = match (generate, password_from_env) {
                (Some(length), _) => generated(length)?,
                (None, true) => entry_password_from_env()?,
                (None, false) => current.password.clone(),
            };
            let changed = local.vault_mut().update_entry(
                &id,
                &EntryInput {
                    title: current.title.clone(),
                    url: url.unwrap_or_else(|| current.url.clone()),
                    username: username.unwrap_or_else(|| current.username.clone()),
                    password,
                    notes: notes.unwrap_or_else(|| current.notes.clone()),
                },
            )?;
            if changed {
                local.save()?;
                println!("entrée modifiée : {title}");
            } else {
                println!("aucun changement");
            }
        }
        Command::Remove { vault, title } => {
            let mut local = open(&vault)?;
            let id = find(&local, &title)?;
            local.vault_mut().delete_entry(&id)?;
            local.save()?;
            println!("entrée supprimée : {title}");
        }
        Command::Merge { vault, other } => {
            let key = vault_key(&vault)?;
            let mut local = LocalVault::open(&vault.file, key.clone(), OpenLimits::default())?;
            let bytes = storage::read_vault(&other)?;
            let other = ligrivsstore_core::Vault::open(&bytes, &key, &OpenLimits::default())?;
            let report = local.vault_mut().merge_from(&other)?;
            local.save()?;
            println!(
                "fusion : {} ajout(s), {} mise(s) à jour, {} suppression(s), {} déplacement(s)",
                report.created, report.updated, report.deleted, report.relocated
            );
            for warning in report.warnings {
                println!("avertissement : {warning}");
            }
        }
        Command::Sync {
            vault,
            server,
            new_credentials,
        } => {
            let mut local = open(&vault)?;
            let transport = transport(&server)?;
            if new_credentials {
                local.accept_new_credentials()?;
            }
            let started = Instant::now();
            let report = local.sync(&transport, &SyncOptions::default())?;
            println!(
                "synchronisé en {} ms : téléchargé {}, fusion {} changement(s), envoyé {}, conflits {}, relectures {}",
                started.elapsed().as_millis(),
                yes_no(report.downloaded),
                report.merge.created
                    + report.merge.updated
                    + report.merge.deleted
                    + report.merge.relocated,
                yes_no(report.uploaded),
                report.conflicts,
                report.weak_waits
            );
        }
        Command::Clone { vault, server } => {
            let transport = transport(&server)?;
            let local = LocalVault::clone_from_remote(
                &vault.file,
                vault_key(&vault)?,
                OpenLimits::default(),
                &transport,
            )?;
            println!(
                "coffre installé : {} ({} entrées)",
                local.path().display(),
                local.vault().entries().len()
            );
        }
        Command::Keyfile { path } => {
            keyfile::create(&path)?;
            println!(
                "fichier clé créé : {} (format XML 2.0 de KeePass)",
                path.display()
            );
            println!("conservez-en une copie à part : sans lui, le coffre ne s'ouvre plus");
        }
        Command::Info { file } => {
            let bytes = storage::read_vault(&file)?;
            let info = header::inspect(&bytes)?;
            println!("format : KDBX {}.{}", info.major, info.minor);
            println!("chiffrement : {:?}", info.cipher);
            println!("dérivation : {}", info.kdf);
            match OpenLimits::default().check(&info) {
                Ok(()) => println!("plafonds d'ouverture : respectés"),
                Err(error) => println!("plafonds d'ouverture : {error}"),
            }
        }
        Command::Backups { vault } => {
            let local = open(&vault)?;
            for backup in local.backups()? {
                println!("{}\t{} octets", backup.path.display(), backup.size);
            }
        }
        Command::Generate {
            length,
            no_symbols,
            no_digits,
            no_uppercase,
            no_lowercase,
            exclude_ambiguous,
        } => {
            let policy = PasswordPolicy {
                length,
                lowercase: !no_lowercase,
                uppercase: !no_uppercase,
                digits: !no_digits,
                symbols: !no_symbols,
                exclude_ambiguous,
            };
            println!("{}", generate_password(&policy)?.as_str());
            eprintln!("entropie : {:.0} bits", policy.entropy_bits());
        }
        Command::Calibrate { target_ms } => {
            let params = KdfParams::calibrate(Duration::from_millis(target_ms))?;
            println!(
                "Argon2id, {} Mio, {} voies : {} itérations pour environ {target_ms} ms sur ce poste",
                params.memory_bytes / (1024 * 1024),
                params.parallelism,
                params.iterations
            );
        }
    }
    Ok(())
}

fn vault_key(args: &VaultArgs) -> Result<VaultKey, Error> {
    let mut key = VaultKey::new();
    if let Ok(password) = std::env::var("LGS_PASSWORD") {
        let password = Zeroizing::new(password);
        key = key.with_password(&password);
    }
    if let Some(path) = &args.keyfile {
        let bytes = keyfile::read(path)?;
        key = key.with_keyfile(&bytes)?;
    }
    if key.is_empty() {
        return Err(Error::InvalidInput(
            "phrase de passe absente : définir LGS_PASSWORD (ou fournir --keyfile)".into(),
        ));
    }
    Ok(key)
}

fn open(args: &VaultArgs) -> Result<LocalVault, Error> {
    LocalVault::open(&args.file, vault_key(args)?, OpenLimits::default())
}

fn find(local: &LocalVault, title: &str) -> Result<String, Error> {
    let matches: Vec<_> = local
        .vault()
        .entries()
        .into_iter()
        .filter(|e| e.title == title)
        .collect();
    match matches.as_slice() {
        [single] => Ok(single.id.clone()),
        [] => Err(Error::EntryNotFound(title.to_owned())),
        _ => Err(Error::InvalidInput(format!(
            "plusieurs entrées portent le titre « {title} »"
        ))),
    }
}

fn transport(server: &ServerArgs) -> Result<WebDavTransport, Error> {
    let password = Zeroizing::new(std::env::var("LGS_WEBDAV_PASSWORD").map_err(|_| {
        Error::InvalidInput("mot de passe WebDAV absent : définir LGS_WEBDAV_PASSWORD".into())
    })?);
    match &server.ca_file {
        Some(path) => {
            let pem = std::fs::read(path)?;
            Ok(WebDavTransport::with_root_ca(
                &server.url,
                &server.user,
                &password,
                &pem,
            )?)
        }
        None => Ok(WebDavTransport::new(&server.url, &server.user, &password)?),
    }
}

fn entry_password_from_env() -> Result<Zeroizing<String>, Error> {
    std::env::var("LGS_ENTRY_PASSWORD")
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::InvalidInput(
                "mot de passe de l'entrée absent : définir LGS_ENTRY_PASSWORD ou utiliser --generate".into(),
            )
        })
}

fn generated(length: usize) -> Result<Zeroizing<String>, Error> {
    generate_password(&PasswordPolicy {
        length,
        ..PasswordPolicy::default()
    })
}

fn yes_no(value: bool) -> &'static str {
    if value { "oui" } else { "non" }
}
