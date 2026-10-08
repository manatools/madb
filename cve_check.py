#!/usr/bin/env python3

"""
This fetches a selection of update message ids from datagrepper to use for
checking Mageia packages versions.
"""
import json
import os
import csv
import re
import logging
import subprocess
from collections import namedtuple
from madb.dnf5madbbase import Dnf5MadbBase
import madb.config as config

from sqlalchemy import Column, Integer, String, Boolean, DateTime, UniqueConstraint, create_engine, update, select, delete, text, event
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timedelta, timezone

import argparse

try:
    import semver
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Le module 'semver' est requis pour comparer les versions "
        "(pip install semver)."
    ) from exc

try:
    from rapidfuzz import fuzz
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Le module 'rapidfuzz' est requis pour le rapprochement approché "
        "des noms de paquets (pip install rapidfuzz)."
    ) from exc

Base = declarative_base()

# Définir la table Package
class Package(Base):
    __tablename__ = 'packages'
    __table_args__ = (UniqueConstraint('name', 'distro', name='uq_package_name_distro'),)
    id = Column(Integer, primary_key=True)
    name = Column(String(80))
    our_version = Column(String(20))
    upstream_version = Column(String(20))
    updated_on = Column(DateTime)
    pkg_id = Column(Integer)
    summary = Column(String(80))
    url = Column(String(255))
    description = Column(String(2000))
    # Numéro de version de la distribution (ex: 10 pour TOP_RELEASE, 11
    # pour la version de développement si TOP_RELEASE=10). Un même nom de
    # paquet peut donc avoir plusieurs lignes, une par distro suivie,
    # avec des versions installées potentiellement différentes.
    distro = Column(Integer)


# Table de suivi des CVE déjà examinés, pour ne traiter que les
# nouveautés à chaque intervalle. On part du principe (à revoir si besoin)
# que les fichiers JSON ne sont jamais modifiés après publication : un CVE
# une fois marqué comme traité ne sera donc jamais réexaminé.
class ProcessedCve(Base):
    __tablename__ = 'processed_cves'
    cve_id = Column(String(32), primary_key=True)
    processed_on = Column(DateTime)


# Correspondances product/paquet incertaines (rapprochement approché par
# nom et/ou URL), proposées pour revue humaine plutôt qu'auto-validées.
class CveCandidate(Base):
    __tablename__ = 'cve_candidates'
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(32))
    product = Column(String(120))
    package_name = Column(String(80))
    distro = Column(Integer)  # numéro de version de la distribution concernée
    score = Column(Integer)
    name_score = Column(Integer)
    url_score = Column(Integer)
    matched_url = Column(String(255))
    affected = Column(Boolean)  # None si indéterminé (pas de our_version, etc.)
    created_on = Column(DateTime)


# Journal de TOUTES les tentatives de rapprochement product -> paquet, quel
# qu'en soit le résultat (y compris un échec total). Sert à diagnostiquer
# où une correspondance attendue se perd : absence de product, absence de
# paquet du tout dans la base, score trop bas, ou correspondance trouvée
# mais qui échoue ensuite au contrôle de version (donc invisible côté
# alertes ET côté candidats). Enregistré AVANT toute application du filtre
# de version, indépendamment de son résultat.
class CveMatchLog(Base):
    __tablename__ = 'cve_match_log'
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(32))
    product = Column(String(120))
    # 'exception' | 'exact' | 'fuzzy_candidates' | 'no_match'
    resolution = Column(String(20))
    package_name = Column(String(80))  # renseigné si resolution in (exception, exact)
    distro = Column(Integer)  # numéro de version de la distribution concernée
    pool_size = Column(Integer)  # nb de paquets comparés lors du passage approché (0/NULL sinon)
    best_score = Column(Integer)  # meilleur score obtenu lors du passage approché, même sous le seuil
    has_our_version = Column(Boolean)  # pour une résolution confiante : our_version était-elle renseignée ?
    affected_verdict = Column(Boolean)  # résultat de check_package_affected pour une résolution confiante
    created_on = Column(DateTime)


database_path = os.path.join(config.EXTERNAL_PATH, 'packages.db')
engine = create_engine('sqlite:///' + database_path, echo=False)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """WAL réduit fortement le coût des commits fréquents (pas de réécriture
    complète du fichier principal à chaque fsync), et synchronous=NORMAL
    est sûr en WAL (on ne perd au pire que les toutes dernières
    transactions en cas de crash brutal, jamais la base elle-même)."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


# Création des tables si elles n'existent pas
Base.metadata.create_all(engine)


def _migrate_packages_add_distro(conn):
    """Les versions antérieures du script ne connaissaient qu'une seule
    version de la distribution, et 'name' seul était UNIQUE. SQLite ne
    permet pas de retirer une contrainte UNIQUE existante par un simple
    ALTER TABLE : il faut recréer la table avec la nouvelle contrainte
    (name, distro) et recopier les données. Les paquets déjà en base sont
    rattachés à la version de développement actuelle (TOP_RELEASE + 1),
    seule version connue jusqu'ici."""
    dev_number = config.TOP_RELEASE + 1
    conn.execute(text("ALTER TABLE packages RENAME TO packages_old"))
    conn.execute(text("""
        CREATE TABLE packages (
            id INTEGER NOT NULL PRIMARY KEY,
            name VARCHAR(80),
            our_version VARCHAR(20),
            upstream_version VARCHAR(20),
            updated_on DATETIME,
            pkg_id INTEGER,
            summary VARCHAR(80),
            url VARCHAR(255),
            description VARCHAR(2000),
            distro INTEGER,
            UNIQUE (name, distro)
        )
    """))
    conn.execute(text(
        "INSERT INTO packages "
        "(id, name, our_version, upstream_version, updated_on, pkg_id, summary, url, description, distro) "
        "SELECT id, name, our_version, upstream_version, updated_on, pkg_id, summary, url, description, :dev_number "
        "FROM packages_old"
    ), {'dev_number': dev_number})
    conn.execute(text("DROP TABLE packages_old"))
    conn.commit()
    logging.info(
        "Migration : packages.distro ajoutée, paquets existants rattachés à la version %s.",
        dev_number,
    )


def ensure_schema(engine):
    """create_all() ne modifie pas les tables déjà existantes : on ajoute
    ici les colonnes manquantes pour rester compatible avec une base créée
    par une version antérieure du script (ajout de packages.url, puis
    packages.description, puis le support multi-distributions)."""
    with engine.connect() as conn:
        cols = [row[1] for row in conn.execute(text("PRAGMA table_info(packages)"))]
        if 'url' not in cols:
            conn.execute(text("ALTER TABLE packages ADD COLUMN url VARCHAR(255)"))
            conn.commit()
        if 'description' not in cols:
            conn.execute(text("ALTER TABLE packages ADD COLUMN description VARCHAR(2000)"))
            conn.commit()
        if 'distro' not in cols:
            _migrate_packages_add_distro(conn)

        for table in ('cve_match_log', 'cve_candidates'):
            table_cols = [row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))]
            if table_cols and 'distro' not in table_cols:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN distro INTEGER"))
                conn.commit()


ensure_schema(engine)

# Session pour insérer ou interagir avec la base
Session = sessionmaker(bind=engine)


def _safe_get_description(package):
    """Appel défensif à get_description() : contrairement à get_url(), sa
    présence sur l'objet paquet (Dnf5MadbBase) n'a pas été confirmée. Si
    la méthode n'existe pas, on stocke simplement None plutôt que de faire
    échouer toute la mise à jour de la base."""
    getter = getattr(package, 'get_description', None)
    if getter is None:
        return None
    try:
        return getter()
    except Exception as exc:
        logging.debug("get_description() a échoué pour %s : %s", package.get_name(), exc)
        return None


# Fonction d'ajout d'un package
def add_package(session, name, our_version, upstream_version, updated_on, pkg_id, summary, url=None, description=None, distro=None):
    package = Package(name=name,
                      our_version=our_version, 
                      upstream_version=upstream_version, 
                      updated_on=updated_on, 
                      pkg_id=pkg_id,
                      summary=summary,
                      url=url,
                      description=description,
                      distro=distro)
    session.add(package)
    session.commit()

# Fonction de retrait d'un package
def remove_package(session, id):
    package = session.get(Package, id)
    session.delete(package)
    session.commit()

# Fonction de mise à jour d'un package
def update_package(session, id, our_version, upstream_version, updated_on, pkg_id,):
    package = session.get(Package, id)
    if our_version != "":
        package.our_version = our_version
    if upstream_version != "":
        package.upstream_version = upstream_version
    package.updated_on = updated_on
    package.pkg_id = pkg_id
    session.commit()


def cleaning(session, packages_list, distro):
    """Supprime les paquets de CETTE distribution qui ne sont plus listés
    - sans toucher aux autres distributions suivies, dont les paquets
    partagent la même colonne 'name' mais une valeur 'distro' propre."""
    stmt = delete(Package).where(Package.distro == distro, Package.name.notin_(packages_list))
    session.execute(stmt)
    session.commit()


def get_distro_targets():
    """Les trois versions de la distribution suivies : la version de
    développement (dépôt config.DEV_NAME, numérotée TOP_RELEASE + 1), la
    dernière version stable (TOP_RELEASE) et la précédente
    (TOP_RELEASE - 1). Retourne une liste de (instance Dnf5MadbBase,
    numéro de distro). Construites à la demande (pas au chargement du
    module) pour ne pas payer ce coût sur les commandes qui n'en ont pas
    besoin (--list-candidates, --export-html...)."""
    return [
        (Dnf5MadbBase(config.DEV_NAME, "x86_64", config.DATA_PATH), config.TOP_RELEASE + 1),
        (Dnf5MadbBase(str(config.TOP_RELEASE), "x86_64", config.DATA_PATH), config.TOP_RELEASE),
        (Dnf5MadbBase(str(config.TOP_RELEASE - 1), "x86_64", config.DATA_PATH), config.TOP_RELEASE - 1),
    ]


def update_packages_db(force=False):
    """Peuple/actualise la base pour chacune des versions de distribution
    suivies (get_distro_targets). Un paquet est identifié par (name,
    distro) : un même nom peut donc avoir plusieurs lignes, une par
    version suivie, avec des our_version potentiellement différentes."""
    for distro_obj, distro_number in get_distro_targets():
        logging.info("Mise à jour des paquets pour la distribution %s", distro_number)
        packages = get_srpms(distro_obj)
        with Session() as session:
            for package in packages:
                logging.debug(package.get_name())
                # check if record exists
                name_to_find = package.get_name()
                stmt = select(Package).where(
                    Package.name == name_to_find, Package.distro == distro_number
                )
                result = session.execute(stmt).scalar_one_or_none()
                if result:
                    if (package.get_version() != result.our_version) or force:
                        # update our version
                        logging.debug("Updating")
                        stmt = update(Package).\
                            where(Package.id == result.id).\
                            values(
                                our_version=package.get_version(),
                                summary=package.get_summary(),
                                url=package.get_url(),
                                description=_safe_get_description(package),
                                )
                        session.execute(stmt)
                        logging.debug("Updated")
                else:
                    logging.debug("Adding")
                    add_package(session,
                                name_to_find,
                                package.get_version(),
                                "",
                                None,
                                None,
                                package.get_summary(),
                                package.get_url(),
                                _safe_get_description(package),
                                distro_number,
                                )
                    logging.debug("Added")

            # delete srpms no more listés POUR CETTE DISTRIBUTION
            cleaning(session, [pkg.get_name() for pkg in packages], distro_number)
            session.commit()


def get_srpms(distro_obj):
    return distro_obj.search_nevra(["*"], repo="*SRPMS*")


# ---------------------------------------------------------------------------
# Vérification des CVE
# ---------------------------------------------------------------------------

def run_git(args, cwd=None):
    result = subprocess.run(
        ['git'] + args, cwd=cwd, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def sync_repo(repo_path, repo_url):
    """Clone le dépôt cvelistV5 s'il n'existe pas encore localement, sinon
    le met à jour. On n'a pas besoin de l'historique complet puisque les
    "nouveautés" sont déterminées via la table processed_cves et non via un
    diff git."""
    if not os.path.isdir(os.path.join(repo_path, '.git')):
        logging.info("Clonage de %s dans %s", repo_url, repo_path)
        parent = os.path.dirname(repo_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        run_git(['clone', '--depth', '50', repo_url, repo_path])
    else:
        logging.info("Mise à jour du dépôt %s", repo_path)
        run_git(['pull', '--ff-only'], cwd=repo_path)


def load_exceptions(path):
    """Charge la table d'exceptions product -> nom de paquet depuis un
    fichier CSV à deux colonnes (product, name). Une entrée absente du
    fichier est mappée sur elle-même par défaut."""
    exceptions = {}
    if path and os.path.exists(path):
        with open(path, newline='', encoding='utf-8') as f:
            for row in csv.reader(f):
                if not row or row[0].strip().startswith('#'):
                    continue
                if len(row) < 2:
                    continue
                product, name = row[0].strip(), row[1].strip()
                if product:
                    exceptions[product] = name
    return exceptions


def load_strangers(path):
    """Charge la table des étrangers vendor, product depuis un
    fichier CSV à deux colonnes (vendor, product)."""
    strangers = []
    if path and os.path.exists(path):
        with open(path, newline='', encoding='utf-8') as f:
            for row in csv.reader(f):
                if not row or row[0].strip().startswith('#'):
                    continue
                if len(row) < 2:
                    continue
                vendor, product = row[0].strip(), row[1].strip()
                strangers.append( (vendor, product,) )
    return strangers


def iter_cve_files(repo_path):
    """Parcourt l'arborescence cves/ du dépôt et retourne le chemin de
    chaque fichier JSON de CVE."""
    cves_dir = os.path.join(repo_path, 'cves')
    for root, _dirs, files in os.walk(cves_dir):
        for fname in files:
            if fname.startswith('CVE-') and fname.endswith('.json'):
                yield os.path.join(root, fname)


def load_cve_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def get_cve_id(cve_json):
    return cve_json.get('cveMetadata', {}).get('cveId')


def get_published_date(cve_json):
    date_str = cve_json.get('cveMetadata', {}).get('datePublished')
    if not date_str:
        return None
    try:
        parsed = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # Date sans fuseau : on suppose UTC pour rester comparable à cutoff.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


_CVE_ID_RE = re.compile(r'^CVE-(\d{4})-(\d+)$')


def cve_file_path(repo_path, cve_id):
    """Chemin du fichier JSON d'un CVE, déduit directement de son id selon
    la convention du dépôt (cves/<année>/<Nxxx>/CVE-<année>-<numéro>.json,
    par lots de 1000) - sans avoir à parcourir l'arborescence. Retourne
    None si l'id ne suit pas le format attendu."""
    match = _CVE_ID_RE.match(cve_id)
    if not match:
        return None
    year, number = match.groups()
    bucket = f"{int(number) // 1000}xxx"
    return os.path.join(repo_path, 'cves', year, bucket, f"{cve_id}.json")


def load_cve_by_id(repo_path, cve_id):
    """Charge le JSON d'un CVE à partir de son seul id. Retourne None si
    le fichier est introuvable ou illisible (dépôt local désynchronisé,
    id invalide...)."""
    path = cve_file_path(repo_path, cve_id)
    if not path or not os.path.exists(path):
        return None
    try:
        return load_cve_json(path)
    except (json.JSONDecodeError, OSError):
        return None


def get_affected_product(affected_record):
    """Le nom de produit d'une entrée 'affected' donnée. Un même CVE peut
    contenir plusieurs entrées 'affected', chacune concernant un produit
    (donc potentiellement un paquet) différent."""
    return affected_record.get('product')


def get_affected_vendor(affected_record):
    """Le nom de produit d'une entrée 'affected' donnée. Un même CVE peut
    contenir plusieurs entrées 'affected', chacune concernant un produit
    (donc potentiellement un paquet) différent."""
    return affected_record.get('vendor')


def get_affected_repo_url(affected_record):
    """L'URL du dépôt source d'une entrée 'affected' (champ 'repo'), à la
    même granularité que 'product'. Quand elle est renseignée, c'est le
    signal le plus fiable, mais 'repo' est souvent absent."""
    return affected_record.get('repo')


# Tags de référence qui indiquent en général un site RAPPORTANT la
# vulnérabilité (avis tiers, description technique d'un chercheur...)
# plutôt qu'une page appartenant au projet lui-même. Peu fiables comme
# signal d'identité du logiciel, donc exclus.
_REFERENCE_EXCLUDED_TAGS = {'technical-description', 'third-party-advisory'}

# Domaines de plateformes qui rapportent/agrègent des vulnérabilités,
# jamais l'origine du logiciel concerné. Liste volontairement restreinte
# aux cas manifestes ; à compléter au besoin.
_REFERENCE_EXCLUDED_DOMAINS = {
    'vulncheck.com',
    'nvd.nist.gov',
    'cve.org',
    'cve.mitre.org',
}


def get_cve_reference_urls(cve_json):
    """URLs des références du CVE (containers.cna.references[]), filtrées
    pour ne garder que celles susceptibles de pointer vers le logiciel
    source lui-même (tags comme 'product', 'patch', 'vendor-advisory'...)
    plutôt que vers un site qui rapporte la vulnérabilité. Vient en
    complément du champ 'repo' de chaque entrée 'affected', qui n'est pas
    toujours renseigné. Utilisé pour le score des candidats approchés
    (niveau 3) : plus permissif, car une URL différente de celle du
    paquet n'y est qu'un indice parmi d'autres, pas un verdict."""
    refs = cve_json.get('containers', {}).get('cna', {}).get('references', [])
    urls = []
    for ref in refs:
        url = ref.get('url')
        if not url:
            continue
        tags = set(ref.get('tags') or [])
        if tags & _REFERENCE_EXCLUDED_TAGS:
            continue
        normalized = normalize_url(url)
        if normalized and normalized.split('/', 1)[0] in _REFERENCE_EXCLUDED_DOMAINS:
            continue
        urls.append(url)
    return urls


def get_cve_product_reference_urls(cve_json):
    """Sous-ensemble des références explicitement taguées 'product' :
    celles qui REVENDIQUENT être la page du logiciel lui-même. Utilisé
    uniquement pour décider de contester un match de nom exact (avec
    'repo'), jamais pour le score des candidats. Une référence 'patch',
    'issue-tracking' ou autre n'affirme rien sur l'identité du projet -
    l'absence de recoupement avec l'URL du paquet n'y est pas un signal
    fiable de désaccord (l'URL 'informative' du paquet pointe souvent
    ailleurs que la référence citée, même pour le bon projet)."""
    refs = cve_json.get('containers', {}).get('cna', {}).get('references', [])
    return [
        ref.get('url') for ref in refs
        if ref.get('url') and 'product' in (ref.get('tags') or [])
    ]


def get_affected_entries(cve_json):
    return cve_json.get('containers', {}).get('cna', {}).get('affected', [])


def find_affected_record(cve_json, product):
    """Retrouve la première entrée 'affected' dont le product correspond
    exactement (un CVE peut en contenir plusieurs pour des produits
    différents ; on veut celle qui a effectivement produit ce match)."""
    for record in get_affected_entries(cve_json):
        if record.get('product') == product:
            return record
    return None


def get_cve_title(cve_json):
    return cve_json.get('containers', {}).get('cna', {}).get('title') or ''


def get_cve_description(cve_json, lang='en'):
    """Texte descriptif du CVE, en préférant la langue demandée (les CVE
    n'ont pas toujours de version anglaise ; on prend alors la première
    disponible plutôt que de ne rien afficher)."""
    descriptions = cve_json.get('containers', {}).get('cna', {}).get('descriptions', [])
    for desc in descriptions:
        if desc.get('lang', '').lower().startswith(lang):
            return desc.get('value', '')
    return descriptions[0].get('value', '') if descriptions else ''


def format_affected_versions(affected_record):
    """Présentation lisible des plages de versions affectées d'une entrée
    'affected', une ligne par entrée de son tableau 'versions'."""
    if not affected_record:
        return []
    lines = []
    default_status = affected_record.get('defaultStatus')
    if default_status:
        lines.append(f"Statut par défaut : {default_status}")
    for entry in affected_record.get('versions', []):
        status = entry.get('status', '?')
        version = entry.get('version', '?')
        version_type = entry.get('versionType', '?')
        less_than = entry.get('lessThan')
        less_equal = entry.get('lessThanOrEqual')
        if less_than is not None:
            bounds = f"[{version} ; {less_than}["
        elif less_equal is not None:
            bounds = f"[{version} ; {less_equal}]"
        else:
            bounds = f"{version}"
        lines.append(f"{bounds} — {status} ({version_type})")
    return lines


def pick_significant_url(cve_json, affected_record):
    """La meilleure URL disponible pour représenter la source du logiciel,
    par ordre de fiabilité décroissant : repo de l'entrée affected,
    référence taguée 'product', puis n'importe quelle référence filtrée."""
    repo_url = get_affected_repo_url(affected_record) if affected_record else None
    if repo_url:
        return repo_url
    product_refs = get_cve_product_reference_urls(cve_json)
    if product_refs:
        return product_refs[0]
    refs = get_cve_reference_urls(cve_json)
    return refs[0] if refs else None


def load_processed_ids(session):
    """Charge en une seule requête l'ensemble des CVE déjà traités, plutôt
    que d'interroger la base individuellement pour chacun des ~300 000
    fichiers du dépôt à chaque exécution."""
    return set(session.execute(select(ProcessedCve.cve_id)).scalars().all())


def cve_id_from_filename(path):
    """Déduit le cve_id du nom de fichier (convention du dépôt :
    CVE-<année>-<numéro>.json), pour pouvoir écarter un fichier déjà
    traité sans même l'ouvrir ni le parser en JSON."""
    return os.path.splitext(os.path.basename(path))[0]


def mark_processed(session, cve_id):
    """Ajoute le CVE à la session sans committer (le commit est fait par
    lots par l'appelant, pour ne pas ralentir le traitement du premier
    passage qui peut porter sur des centaines de milliers de fichiers)."""
    session.merge(ProcessedCve(cve_id=cve_id, processed_on=datetime.now(timezone.utc)))


def parse_semver(version):
    """Parse une chaîne de version en semver, avec coercition en cas de
    format non strict (ex: '1.2' -> '1.2.0'). Retourne None si impossible.
    La valeur conventionnelle '0' (utilisée dans les entrées CVE pour dire
    'depuis toujours') est traitée comme la version minimale.

    semver.Version (semver >= 3.x) n'a PAS de méthode 'coerce' (elle
    existait dans l'API 2.x, supprimée depuis) : on la réimplémente ici
    à la main, en ne gardant que les composants numériques en tête de
    chaîne, complétés à zéro si besoin. Sans ça, toute version qui n'est
    pas déjà écrite en x.y.z strict (par ex. '6.16' pour le noyau Linux,
    très courant) échouait silencieusement et produisait un verdict
    indéterminé au lieu d'une comparaison correcte."""
    if version is None:
        return None
    version = str(version).strip()
    if version in ('', '0'):
        return semver.Version(0, 0, 0)
    try:
        return semver.Version.parse(version)
    except ValueError:
        pass

    match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', version)
    if not match:
        return None
    major, minor, patch = (g or '0' for g in match.groups())
    try:
        return semver.Version.parse(f"{major}.{minor}.{patch}")
    except ValueError:
        return None


def is_version_affected(our_version, versions_entry):
    """Évalue une seule entrée du tableau 'versions' d'un bloc 'affected'.
    Seules les entrées de type versionType == 'semver' sont prises en
    compte, comme demandé ; les autres sont ignorées (retour None).
    Retourne True/False si l'entrée s'applique à our_version, None sinon."""
    if versions_entry.get('versionType') != 'semver':
        return None

    ours = parse_semver(our_version)
    if ours is None:
        return None

    lower = parse_semver(versions_entry.get('version'))
    if lower is None:
        return None

    in_lower = ours.compare(lower) >= 0

    less_than = versions_entry.get('lessThan')
    less_equal = versions_entry.get('lessThanOrEqual')

    if less_than is not None:
        upper = parse_semver(less_than)
        in_upper = upper is not None and ours.compare(upper) < 0
    elif less_equal is not None:
        upper = parse_semver(less_equal)
        in_upper = upper is not None and ours.compare(upper) <= 0
    else:
        # Pas de borne supérieure : seule la version exacte indiquée est
        # concernée par cette entrée.
        in_upper = ours.compare(lower) == 0

    if not (in_lower and in_upper):
        return None

    return versions_entry.get('status') == 'affected'


# ---------------------------------------------------------------------------
# Rapprochement approché product (CVE) <-> paquet, en complément de la
# table d'exceptions et de l'égalité stricte de nom.
# ---------------------------------------------------------------------------

# Seuil minimal (sur 100) en dessous duquel un candidat n'est même pas
# proposé à la revue, et nombre maximal de candidats conservés par CVE.
CANDIDATE_THRESHOLD = 65
MAX_CANDIDATES = 5

# Seuil requis quand SEUL le nom corrobore (aucune URL en commun,
# url_score == 0) : plus strict que CANDIDATE_THRESHOLD, en filet de
# sécurité contre les mots génériques pas encore identifiés dans
# _GENERIC_PRODUCT_WORDS ci-dessous. En pratique url_score n'est jamais
# une valeur intermédiaire faible (voir url_similarity : soit 0, soit
# >= 75), donc "url_score == 0" équivaut bien à "aucune corroboration".
NAME_ONLY_THRESHOLD = 80

# Mots/tokens sans valeur discriminante pour le rapprochement de noms :
# mentions de vendeur/organisation générales, et affixes de paquetage
# courants qui n'apparaissent en général que d'un seul côté (product du
# CVE ou name du paquet), jamais des deux.
_NAME_STOPWORDS = {
    'apache', 'the', 'project', 'foundation', 'software', 'org',
    'lib', 'lib64', 'python', 'python2', 'python3', 'perl', 'php',
    'ruby', 'nodejs', 'node', 'golang', 'rust',
    'devel', 'dev', 'doc', 'docs', 'common', 'libs', 'utils', 'core',
}

# Descripteurs de catégorie produit très répandus, qui se retrouvent dans
# des dizaines de logiciels sans rapport (ex: 'nats-server' et 'Windows
# Server' n'ont de commun que ce mot). Contrairement à _NAME_STOPWORDS
# (affixes de paquetage), ceux-ci sont de vrais mots du nom produit côté
# CVE comme côté paquet - mais leur fréquence les rend inutilisables
# comme signal de correspondance à eux seuls. Liste à compléter au fil
# des faux positifs observés (voir --list-candidates).
_GENERIC_PRODUCT_WORDS = {
    'server', 'client', 'enterprise', 'extension', 'extensions',
    'builder', 'comment', 'comments', 'manager', 'plugin', 'module',
}


def normalize_name(name):
    """Normalise un nom de produit ou de paquet pour le rapprochement :
    minuscules, découpage en tokens alphanumériques, suppression des mots
    génériques de vendeur/paquetage et des descripteurs de catégorie trop
    répandus. Ex: 'Apache Tomcat' et 'tomcat' donnent tous les deux
    'tomcat' ; 'nats-server' et 'Windows Server' ne partagent plus rien
    une fois 'server' retiré des deux côtés."""
    if not name:
        return ''
    tokens = re.findall(r'[a-z0-9]+', name.lower())
    tokens = [t for t in tokens if t not in _NAME_STOPWORDS and t not in _GENERIC_PRODUCT_WORDS]
    return '-'.join(tokens)


# Domaines génériques hébergeant des centaines de milliers de projets
# distincts : un domaine identique n'y est PAS un signal fiable à lui
# seul (ex: deux projets sans rapport peuvent tous deux être sur
# github.com). Pour ceux-là, on exige en plus que le premier segment de
# chemin (organisation/dépôt) corresponde.
_MULTI_TENANT_HOSTS = {
    'github.com', 'gitlab.com', 'sourceforge.net', 'bitbucket.org',
    'pypi.org', 'npmjs.com', 'crates.io', 'gitee.com', 'codeberg.org',
    'salsa.debian.org', 'code.google.com', 'launchpad.net', 'gitea.com',
}


def normalize_url(url):
    """Normalise une URL pour la comparaison : schéma, 'www.' et suffixe
    '.git' retirés, slash final retiré."""
    if not url:
        return None
    u = url.strip().lower()
    u = re.sub(r'^\w+://', '', u)
    u = re.sub(r'^www\.', '', u)
    u = u.rstrip('/')
    u = re.sub(r'\.git$', '', u)
    return u or None


def url_similarity(url_a, url_b):
    """Score de similarité (0-100) entre deux URLs.

    Le domaine doit être strictement identique pour envisager un score :
    comparer des domaines différents avec un ratio flou sur l'URL entière
    produit de faux positifs (un simple 'https://' ou 'github.com/'
    partagé suffit à faire grimper un partial_ratio). Une fois le domaine
    confirmé identique :
    - domaine dédié au projet (ex: tomcat.apache.org) : signal fiable à
      lui seul, score plancher élevé même si les chemins diffèrent ;
    - domaine générique multi-projets (github.com, etc.) : il faut en
      plus que le premier segment de chemin (organisation/dépôt)
      corresponde, sans quoi le score est nul.
    """
    norm_a, norm_b = normalize_url(url_a), normalize_url(url_b)
    if not norm_a or not norm_b:
        return 0
    if norm_a == norm_b:
        return 100

    domain_a, _, path_a = norm_a.partition('/')
    domain_b, _, path_b = norm_b.partition('/')
    if domain_a != domain_b:
        return 0

    if domain_a not in _MULTI_TENANT_HOSTS:
        if not path_a or not path_b:
            return 75
        return max(75, fuzz.ratio(path_a, path_b))

    org_a = path_a.split('/', 1)[0]
    org_b = path_b.split('/', 1)[0]
    if org_a and org_a == org_b:
        return max(85, fuzz.ratio(path_a, path_b))
    return 0


def best_repo_url_score(candidate_urls, package_url):
    """Meilleur score de similarité entre l'URL du paquet et les URLs
    candidates fournies (typiquement le 'repo' de l'entrée 'affected').
    Retourne (score, url_correspondante)."""
    if not package_url:
        return 0, None
    best_score, best_url = 0, None
    for url in candidate_urls:
        score = url_similarity(url, package_url)
        if score > best_score:
            best_score, best_url = score, url
    return best_score, best_url


def url_index_key(url):
    """Clé d'indexation pour une URL, cohérente avec les règles de
    url_similarity : le domaine seul pour un domaine dédié au projet, le
    couple (domaine, organisation) pour un domaine générique multi-projets
    (sans quoi tout GitHub se retrouverait sous une seule clé)."""
    normalized = normalize_url(url)
    if not normalized:
        return None
    domain, _, path = normalized.partition('/')
    if domain in _MULTI_TENANT_HOSTS:
        org = path.split('/', 1)[0]
        return (domain, org) if org else None
    return (domain,)


PackageIndex = namedtuple(
    'PackageIndex',
    ['packages', 'name_index', 'norm_by_id', 'token_index', 'url_index', 'pkg_by_id', 'pkg_by_name'],
)


def build_package_index(session):
    """Charge tous les paquets une fois par exécution et prépare :
    - norm_by_id : nom normalisé de chaque paquet (évite de le
      recalculer à chaque comparaison) ;
    - name_index : nom normalisé -> paquets REPRÉSENTATIFS (un par nom
      distinct, égalité exacte, niveau 2) ;
    - token_index : chaque mot du nom normalisé -> paquets représentatifs
      qui le partagent, pour ne comparer au niveau 3 qu'un sous-ensemble
      plausible de la base plutôt que la totalité ;
    - url_index : clé d'URL (url_index_key) -> paquets représentatifs
      dont l'URL correspond, pour le même usage côté signal URL ;
    - pkg_by_id : accès direct à un paquet par id ;
    - pkg_by_name : nom -> LISTE de paquets, un par distribution suivie
      où ce nom existe (name n'est plus unique : voir Package.distro).

    Le rapprochement approché (name_index/token_index/url_index) opère
    sur un représentant par nom distinct, pas par ligne : un paquet
    présent dans 3 distributions ne doit pas compter triple ni se
    retrouver en collision avec lui-même au niveau 2. Une fois un NOM
    résolu, l'appelant retrouve toutes ses lignes (une par distribution)
    via pkg_by_name pour générer une alerte/un candidat par distribution.

    Ce filtrage préalable évite de faire tourner fuzz.WRatio/
    url_similarity sur l'ensemble de la base de paquets pour chaque
    'product' non résolu au niveau 1/2, ce qui est le principal poste de
    temps de calcul sur un dépôt CVE de grande taille. Contrepartie
    assumée : un 'product' qui ne partage ni mot ni URL avec aucun paquet
    ne remonte plus aucun candidat, même à très faible score (cas
    attendu comme rare : renommage total sans aucun terme commun)."""
    packages = session.execute(select(Package)).scalars().all()
    norm_by_id = {}
    name_index = {}
    token_index = {}
    url_index = {}
    pkg_by_id = {}
    pkg_by_name = {}

    for pkg in packages:
        pkg_by_id[pkg.id] = pkg
        pkg_by_name.setdefault(pkg.name, []).append(pkg)

    for name, rows in pkg_by_name.items():
        representative = rows[0]
        norm = normalize_name(name)
        for row in rows:
            norm_by_id[row.id] = norm
        name_index.setdefault(norm, []).append(representative)
        for token in norm.split('-'):
            if token:
                token_index.setdefault(token, set()).add(representative.id)
        key = url_index_key(representative.url) if representative.url else None
        if key:
            url_index.setdefault(key, set()).add(representative.id)

    return PackageIndex(packages, name_index, norm_by_id, token_index, url_index, pkg_by_id, pkg_by_name)


def gather_candidate_ids(normalized_product, url_candidates, token_index, url_index):
    """Réunion des paquets plausibles pour un rapprochement approché :
    ceux qui partagent au moins un mot de nom avec le product, plus ceux
    dont l'URL correspond à l'une des url_candidates."""
    ids = set()
    for token in normalized_product.split('-'):
        if token and token in token_index:
            ids |= token_index[token]
    for url in url_candidates:
        key = url_index_key(url)
        if key and key in url_index:
            ids |= url_index[key]
    return ids


def resolve_match(product, url_candidates, authoritative_urls, exceptions, index):
    """Tente de rattacher le 'product' d'une entrée CVE 'affected' à un
    paquet de la base. index est le PackageIndex construit par
    build_package_index.
    - url_candidates : toutes les URLs disponibles (repo + références
      filtrées), utilisées pour le score des candidats approchés
      (niveau 3), où une non-correspondance n'est qu'un indice parmi
      d'autres.
    - authoritative_urls : sous-ensemble plus strict (repo + références
      taguées 'product'), qui REVENDIQUENT être la page du projet.
      Utilisé uniquement pour décider de contester un match de nom exact
      (niveau 2) : une URL 'informative' de paquet ne recoupant aucune
      référence générique n'est pas un signal fiable de désaccord (cas
      courant même pour le bon projet), alors qu'une contradiction avec
      une URL qui se revendique explicitement 'product' l'est.

    Retourne un dict de diagnostic :
    {
        'resolution': 'exception' | 'exact' | 'fuzzy_candidates' | 'no_match',
        'package': Package ou None (résolution confiante uniquement),
        'candidates': liste triée de dicts {package, score, name_score,
                      url_score, matched_url} à faire valider par un
                      humain (résolution 'fuzzy_candidates' uniquement),
        'pool_size': nb de paquets comparés lors du passage approché,
        'best_score': meilleur score obtenu lors du passage approché,
                      même sous le seuil (None si le passage approché n'a
                      pas eu lieu, ou si aucun paquet ne partage un mot
                      ou une URL avec ce product).
    }

    Trois niveaux, du plus au moins fiable :
    1. Exception explicite (exceptions.csv) : product -> nom de paquet.
       Validée par un humain, jamais remise en cause par l'URL.
    2. Égalité exacte des noms normalisés, si elle ne désigne qu'un seul
       paquet (pas d'ambiguïté) ET que rien ne la contredit explicitement
       (voir authoritative_urls ci-dessus) : deux projets sans rapport
       peuvent porter le même nom générique (ex: 'komodo' chez KDE et
       chez moghtech). Le cas retombe alors au niveau 3 pour revue
       humaine plutôt que d'être auto-confirmé.
    3. Score de similarité combiné nom + URL, restreint aux paquets déjà
       en ambiguïté/contestation au niveau 2 s'il y en a, sinon à
       l'union des paquets qui partagent au moins un mot de nom ou une
       URL avec ce product (gather_candidate_ids) - jamais toute la base.
    """
    diag = {
        'resolution': None, 'package': None, 'candidates': [],
        'pool_size': 0, 'best_score': None,
    }

    if product in exceptions:
        rows = index.pkg_by_name.get(exceptions[product])
        if rows:
            diag['resolution'] = 'exception'
            diag['package'] = rows[0]  # représentant ; l'appelant retrouve toutes les distros via pkg_by_name
            return diag
        # Exception mal renseignée (nom de paquet inexistant) : on
        # retombe sur le rapprochement approché ci-dessous plutôt que
        # d'échouer silencieusement.

    normalized_product = normalize_name(product)
    exact_matches = index.name_index.get(normalized_product, [])
    if len(exact_matches) == 1:
        pkg = exact_matches[0]
        if authoritative_urls and pkg.url:
            url_score, _ = best_repo_url_score(authoritative_urls, pkg.url)
            if url_score > 0:
                diag['resolution'] = 'exact'
                diag['package'] = pkg
                return diag
            # Nom identique mais contredit par une URL qui se revendique
            # explicitement 'product' (ou par 'repo') : pas de retour
            # anticipé, on continue vers le passage approché ci-dessous
            # pour que ça remonte comme candidat à trancher.
        else:
            diag['resolution'] = 'exact'
            diag['package'] = pkg
            return diag

    if exact_matches:
        # Collision ou contestation au niveau 2 : on affine seulement
        # parmi ces quelques paquets déjà identifiés par le nom exact.
        pool = exact_matches
    else:
        candidate_ids = gather_candidate_ids(
            normalized_product, url_candidates, index.token_index, index.url_index
        )
        pool = [index.pkg_by_id[i] for i in candidate_ids]

    diag['pool_size'] = len(pool)

    scored = []
    best_score = None
    for pkg in pool:
        name_score = fuzz.WRatio(normalized_product, index.norm_by_id[pkg.id])
        url_score, matched_url = best_repo_url_score(url_candidates, pkg.url)
        combined = max(name_score, url_score)
        best_score = combined if best_score is None else max(best_score, combined)
        # Seuil requis : NAME_ONLY_THRESHOLD (plus strict) si le nom est
        # le seul signal disponible, CANDIDATE_THRESHOLD si l'URL corrobore.
        required = CANDIDATE_THRESHOLD if url_score > 0 else NAME_ONLY_THRESHOLD
        if combined >= required:
            scored.append({
                'package': pkg,
                'score': combined,
                'name_score': name_score,
                'url_score': url_score,
                'matched_url': matched_url,
            })
    scored.sort(key=lambda c: c['score'], reverse=True)
    diag['best_score'] = best_score

    if scored:
        diag['resolution'] = 'fuzzy_candidates'
        diag['candidates'] = scored[:MAX_CANDIDATES]
    else:
        diag['resolution'] = 'no_match'
    return diag


def check_package_affected(our_version, affected_record):
    """affected_record est une entrée de containers.cna.affected[]. On
    parcourt les entrées de son tableau 'versions' dans l'ordre : une
    entrée plus spécifique listée après (par ex. un correctif 'unaffected'
    sur une sous-plage) l'emporte sur les entrées précédentes qui se
    chevauchent, ce qui correspond à la convention usuelle d'écriture de
    ces enregistrements CVE."""
    verdict = None
    for entry in affected_record.get('versions', []):
        result = is_version_affected(our_version, entry)
        if result is not None:
            verdict = result
    return verdict


def examine_cve(session, cve_id, cve_json, exceptions, strangers, index):
    """Examine un CVE déjà chargé : pour chaque entrée 'affected', tente
    le rapprochement avec un paquet (résolution confiante ou candidats),
    journalise dans CveMatchLog, et enregistre les candidats dans
    CveCandidate. Ne touche pas à ProcessedCve (à la charge de
    l'appelant).
    Elimination directe des strangers, identifiés par un vendor et le
    cas échéant un produit.
    Retourne (alertes, nb_candidats_ajoutés)."""
    alerts = []
    candidate_count = 0
    cve_reference_urls = get_cve_reference_urls(cve_json)
    cve_product_reference_urls = get_cve_product_reference_urls(cve_json)
    print(f'Affectés par {cve_id} : {len(get_affected_entries(cve_json))}')
    for affected_record in get_affected_entries(cve_json):
        product = get_affected_product(affected_record)
        vendor = get_affected_vendor(affected_record)
        if not product:
            continue

        stranger_test = False
        for stranger_vendor, stranger_product in strangers:
            if stranger_vendor == vendor:
                if stranger_product in product:
                    stranger_test = True
                    break
        if stranger_test:
            continue
        repo_url = get_affected_repo_url(affected_record)
        url_candidates = ([repo_url] if repo_url else []) + cve_reference_urls
        authoritative_urls = ([repo_url] if repo_url else []) + cve_product_reference_urls

        match = resolve_match(product, url_candidates, authoritative_urls, exceptions, index)

        log_kwargs = dict(
            cve_id=cve_id,
            product=product,
            resolution=match['resolution'],
            pool_size=match['pool_size'],
            best_score=match['best_score'],
            created_on=datetime.now(timezone.utc),
        )

        if match['package']:
            package_rows = index.pkg_by_name.get(match['package'].name, [match['package']])
            for pkg in package_rows:
                verdict = check_package_affected(pkg.our_version, affected_record) if pkg.our_version else None
                session.add(CveMatchLog(
                    package_name=pkg.name,
                    distro=pkg.distro,
                    has_our_version=bool(pkg.our_version),
                    affected_verdict=verdict,
                    **log_kwargs,
                ))
                if verdict:
                    alerts.append({
                        'cve_id': cve_id,
                        'package': pkg.name,
                        'distro': pkg.distro,
                        'our_version': pkg.our_version,
                    })
            continue

        session.add(CveMatchLog(
            package_name=None,
            distro=None,
            has_our_version=None,
            affected_verdict=None,
            **log_kwargs,
        ))

        for candidate in match['candidates']:
            candidate_rows = index.pkg_by_name.get(candidate['package'].name, [candidate['package']])
            for candidate_pkg in candidate_rows:
                verdict = None
                if candidate_pkg.our_version:
                    verdict = check_package_affected(candidate_pkg.our_version, affected_record)
                session.add(CveCandidate(
                    cve_id=cve_id,
                    product=product,
                    package_name=candidate_pkg.name,
                    distro=candidate_pkg.distro,
                    score=candidate['score'],
                    name_score=candidate['name_score'],
                    url_score=candidate['url_score'],
                    matched_url=candidate['matched_url'],
                    affected=verdict,
                    created_on=datetime.now(timezone.utc),
                ))
                candidate_count += 1

    return alerts, candidate_count


def process_new_cves(repo_path, exceptions_path, strangers_path, initial_days):
    """Parcourt les CVE non encore traités, cherche une correspondance avec
    un paquet de la base, et vérifie si la version installée (our_version)
    est concernée. Retourne (nombre_de_cve_examines, liste_des_alertes,
    nombre_de_candidats_a_revoir)."""
    exceptions = load_exceptions(exceptions_path)
    strangers = load_strangers(strangers_path)
    alerts = []
    checked_count = 0
    candidate_count = 0
    seen_since_commit = 0

    with Session() as session:
        index = build_package_index(session)
        processed_ids = load_processed_ids(session)

        # Premier traitement si la table est encore vide : dans ce cas on ne
        # va vérifier que les CVE publiés dans la fenêtre 'initial_days',
        # mais on enregistre quand même TOUS les CVE existants comme
        # "déjà vus", pour que les suivants ne soient pas considérés comme
        # nouveaux à la prochaine exécution.
        is_first_run = not processed_ids
        cutoff = None
        if is_first_run:
            cutoff = datetime.now(timezone.utc) - timedelta(days=initial_days)
            logging.info(
                "Premier traitement : examen limité aux CVE publiés depuis %s",
                cutoff.date(),
            )

        for path in iter_cve_files(repo_path):
            # Le cve_id se déduit du nom de fichier (convention du dépôt) :
            # pour un fichier déjà traité, on l'écarte sans même l'ouvrir
            # ni le parser en JSON, et sans requête SQL individuelle
            # (processed_ids est chargé une seule fois, en mémoire).
            filename_cve_id = cve_id_from_filename(path)
            if filename_cve_id in processed_ids:
                continue

            try:
                cve_json = load_cve_json(path)
            except (json.JSONDecodeError, OSError) as exc:
                logging.warning("Impossible de lire %s : %s", path, exc)
                continue

            cve_id = get_cve_id(cve_json) or filename_cve_id
            if cve_id in processed_ids:
                continue

            if cutoff is not None:
                published = get_published_date(cve_json)
                if published is None or published < cutoff:
                    # Hors fenêtre initiale : on le marque vu sans l'examiner.
                    mark_processed(session, cve_id)
                    processed_ids.add(cve_id)
                    seen_since_commit += 1
                    if seen_since_commit >= 500:
                        session.commit()
                        seen_since_commit = 0
                    continue

            checked_count += 1
            cve_alerts, cve_candidate_count = examine_cve(session, cve_id, cve_json, exceptions, strangers, index)
            alerts.extend(cve_alerts)
            candidate_count += cve_candidate_count

            mark_processed(session, cve_id)
            processed_ids.add(cve_id)
            seen_since_commit += 1
            if seen_since_commit >= 500:
                session.commit()
                seen_since_commit = 0

        session.commit()

    return checked_count, alerts, candidate_count


def rematch_all(repo_path, exceptions_path, stranger_path):
    """Revide cve_match_log et cve_candidates, puis rejoue le
    rapprochement product/paquet sur tous les CVE déjà EXAMINÉS
    (c'est-à-dire ceux qui ont laissé une trace dans cve_match_log avant
    la purge - pas simplement 'vus' hors fenêtre initiale, qui eux
    n'avaient jamais été examinés et ne le seront toujours pas ici).

    Ne resynchronise pas le dépôt git, ne retouche pas processed_cves.
    Utile après une évolution de la logique de rapprochement (URL,
    seuil, exceptions.csv...) pour que l'historique déjà traité reflète
    la version actuelle du script, sans devoir tout retraiter depuis le
    début. Retourne (nombre_de_cve_rejoues, liste_des_alertes,
    nombre_de_candidats)."""
    exceptions = load_exceptions(exceptions_path)
    strangers = load_strangers(stranger_path)

    with Session() as session:
        examined_ids = set(session.execute(select(CveMatchLog.cve_id)).scalars().all())
        if not examined_ids:
            print(
                "cve_match_log est vide : aucun CVE n'a encore été examiné, "
                "rien à rejouer (lancez d'abord un traitement normal)."
            )
            return 0, [], 0

        session.execute(delete(CveMatchLog))
        session.execute(delete(CveCandidate))
        session.commit()

        index = build_package_index(session)

        alerts = []
        candidate_count = 0
        rematched_count = 0
        seen_since_commit = 0

        for path in iter_cve_files(repo_path):
            filename_cve_id = cve_id_from_filename(path)
            if filename_cve_id not in examined_ids:
                continue

            try:
                cve_json = load_cve_json(path)
            except (json.JSONDecodeError, OSError) as exc:
                logging.warning("Impossible de lire %s : %s", path, exc)
                continue

            cve_id = get_cve_id(cve_json) or filename_cve_id
            rematched_count += 1

            cve_alerts, cve_candidate_count = examine_cve(session, cve_id, cve_json, exceptions, strangers, index)
            alerts.extend(cve_alerts)
            candidate_count += cve_candidate_count

            seen_since_commit += 1
            if seen_since_commit >= 500:
                session.commit()
                seen_since_commit = 0

        session.commit()

    return rematched_count, alerts, candidate_count


def summarize_match_log(near_miss_count=15):
    """Affiche une synthèse de cve_match_log : répartition par type de
    résolution, puis les 'quasi-ratés' les plus prometteurs (meilleur
    score obtenu mais sous le seuil CANDIDATE_THRESHOLD), et les
    correspondances confiantes dont le contrôle de version a échoué (donc
    invisibles côté alertes ET côté candidats). Utile pour diagnostiquer
    un manque de candidats ou d'alertes."""
    with Session() as session:
        rows = session.execute(select(CveMatchLog)).scalars().all()

    if not rows:
        print(
            "Le journal cve_match_log est vide : aucune entrée 'affected' "
            "avec un product n'a encore été examinée (vérifiez que de "
            "nouveaux CVE ont bien été traités)."
        )
        return rows

    by_resolution = {}
    for row in rows:
        by_resolution.setdefault(row.resolution, []).append(row)

    print(f"{len(rows)} tentative(s) de rapprochement enregistrée(s) :")
    # for resolution in ('exception', 'exact', 'fuzzy_candidates', 'no_match'):
    #     print(f" - {resolution}: {len(by_resolution.get(resolution, []))}")

    no_match = by_resolution.get('no_match', [])
    if no_match:
        empty_pool = [r for r in no_match if not r.pool_size]
        if empty_pool:
            print(
                f"   dont {len(empty_pool)} avec un pool de paquets vide : "
                "la base 'packages' est-elle bien peuplée (--update-packages) ?"
            )
        near_misses = sorted(
            (r for r in no_match if r.best_score is not None),
            key=lambda r: r.best_score, reverse=True,
        )[:near_miss_count]
        if near_misses:
            print(f"   meilleurs scores manqués (seuil actuel : {CANDIDATE_THRESHOLD}) :")
            for r in near_misses:
                print(f"     - {r.cve_id} : '{r.product}' -> score {r.best_score} (pool {r.pool_size})")

    confident = by_resolution.get('exception', []) + by_resolution.get('exact', [])
    no_version = [r for r in confident if not r.has_our_version]
    indeterminate = [r for r in confident if r.has_our_version and r.affected_verdict is None]
    not_affected = [r for r in confident if r.has_our_version and r.affected_verdict is False]

    if no_version or indeterminate or not_affected:
        print(
            f"   sur {len(confident)} correspondance(s) confiante(s) trouvée(s) "
            "(paquet identifié) qui n'a pas produit d'alerte :"
        )
        if no_version:
            print(f"     - {len(no_version)} sans our_version renseignée dans la base")
        if indeterminate:
            print(
                f"     - {len(indeterminate)} indéterminée(s) : aucune entrée "
                "versionType == 'semver' exploitable (ex: plages en hash git, "
                "cas fréquent pour le noyau Linux)"
            )
        if not_affected:
            print(f"     - {len(not_affected)} effectivement jugée(s) non affectée(s) (version hors plage)")
            for r in not_affected[:near_miss_count]:
                print(f"         - {r.cve_id} : '{r.product}' -> {r.package_name}")

    return rows


def list_pending_candidates():
    """Affiche les correspondances product -> paquet non encore tranchées,
    triées par score décroissant, pour une revue manuelle. Une ligne par
    distribution où le paquet candidat existe (une même paire
    product/package peut apparaître plusieurs fois, une fois par
    distro, avec potentiellement des verdicts différents)."""
    with Session() as session:
        rows = session.execute(
            select(CveCandidate).order_by(CveCandidate.score.desc())
        ).scalars().all()

    if not rows:
        print("Aucun candidat en attente de revue.")
        return rows

    print(f"{len(rows)} candidat(s) en attente de revue :")
    for row in rows:
        verdict = {True: "affecté", False: "non affecté", None: "indéterminé"}[row.affected]
        via = []
        if row.name_score:
            via.append(f"nom={row.name_score}")
        if row.url_score:
            via.append(f"url={row.url_score}")
            if row.matched_url:
                via.append(row.matched_url)
        distro_txt = f"[Mageia {row.distro}] " if row.distro else ""
        print(
            f" - {row.cve_id} : '{row.product}' -> {distro_txt}{row.package_name} "
            f"(score {row.score}, {', '.join(via)}, {verdict})"
        )
    return rows


# ---------------------------------------------------------------------------
# Rapport HTML interactif (liste + détail)
# ---------------------------------------------------------------------------

# Nom interne du champ personnalisé Bugzilla "Source RPM", confirmé par des
# requêtes réelles observées contre bugs.mageia.org
# (buglist.cgi?...&field0-0-0=cf_rpmpkg&type0-0-0=substring&value0-0-0=...).
BUGZILLA_SOURCE_RPM_FIELD = 'cf_rpmpkg'

# Nom interne du champ personnalisé Bugzilla "CVE". CONTRAIREMENT à
# cf_rpmpkg ci-dessus, je n'ai trouvé aucune requête réelle qui confirme ce
# nom : c'est une supposition par analogie de schéma de nommage
# (cf_rpmpkg -> cf_cve), pas une valeur vérifiée. Si les tickets attendus
# n'apparaissent jamais dans le rapport alors que vous savez qu'ils
# existent, corrigez cette constante (visible dans les champs cachés du
# formulaire de recherche avancée de votre Bugzilla, ou dans l'export CSV
# d'une recherche existante filtrée sur CVE).
BUGZILLA_CVE_FIELD = 'cf_cve'

BUGZILLA_PRODUCT = 'Mageia'
BUGZILLA_SECURITY_COMPONENT = 'Security'


def _bugzilla_query(base_url, params, timeout=10):
    """Interroge buglist.cgi en CSV (ctype=json renvoie une erreur sur
    cette instance : le patron de sortie JSON n'y existe pas) et retourne
    une liste de {'id': int, 'title': str, 'url': str}. Ne lève jamais :
    toute erreur réseau ou de format de réponse est journalisée en
    warning et retourne une liste vide, pour ne jamais faire échouer
    l'appelant à cause d'un ticket introuvable.

    Force deux paramètres indispensables, confirmés par des exemples
    réels de requêtes Bugzilla :
    - query_format=advanced : sans lui, les paramètres de filtre par
      champ personnalisé (field0-0-0/type0-0-0/value0-0-0) ne sont pas
      forcément interprétés comme un filtre - la recherche peut alors
      ignorer silencieusement le critère au lieu de le refuser.
    - bug_status=__open__ : sans indication explicite de statut, la
      recherche Bugzilla se limite par défaut à un sous-ensemble de
      statuts ouverts (UNCONFIRMED/NEW/ASSIGNED/REOPENED), ce qui peut
      exclure certains statuts ouverts propres au workflow de cette
      instance. __open__ couvre tous les statuts ouverts tels que
      configurés ici."""
    from urllib.parse import urlencode
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    import csv
    import io

    query_params = dict(params)
    query_params['ctype'] = 'csv'
    query_params['query_format'] = 'advanced'
    query_params['bug_status'] = '__open__'
    url = base_url.rstrip('/') + '/buglist.cgi?' + urlencode(query_params, doseq=True)
    try:
        request = Request(url, headers={'Accept': 'text/csv', 'User-Agent': 'madb'})
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode('utf-8', errors='replace')
    except (URLError, TimeoutError, OSError) as exc:
        logging.warning("Requête Bugzilla échouée (%s) : %s", url, exc)
        return []

    try:
        reader = csv.DictReader(io.StringIO(raw))
        rows = list(reader)
    except csv.Error as exc:
        logging.warning("Réponse CSV Bugzilla illisible (%s) : %s", url, exc)
        return []

    results = []
    for row in rows:
        bug_id_raw = row.get('bug_id') or row.get('id')
        if not bug_id_raw:
            continue
        try:
            bug_id = int(bug_id_raw)
        except ValueError:
            continue
        title = row.get('short_desc') or row.get('summary') or ''
        results.append({
            'id': bug_id,
            'title': title,
            'url': base_url.rstrip('/') + f'/show_bug.cgi?id={bug_id}',
        })
    return results


def bugzilla_tickets_for_package(base_url, package_name):
    """Tickets de composant Security dont le champ Source RPM contient le
    nom du paquet."""
    return _bugzilla_query(base_url, {
        'columnlist': 'bug_id,short_desc',
        'product': BUGZILLA_PRODUCT,
        'component': BUGZILLA_SECURITY_COMPONENT,
        'field0-0-0': BUGZILLA_SOURCE_RPM_FIELD,
        'type0-0-0': 'substring',
        'value0-0-0': package_name,
    })


def bugzilla_tickets_for_cve(base_url, cve_id):
    """Tickets de composant Security mentionnant le CVE dans le champ CVE
    ou dans le titre. Deux requêtes distinctes puis fusion/dédoublonnage
    par id, plus robuste qu'un OR combiné en un seul chart booléen."""
    by_field = _bugzilla_query(base_url, {
        'columnlist': 'bug_id,short_desc',
        'product': BUGZILLA_PRODUCT,
        'component': BUGZILLA_SECURITY_COMPONENT,
        'field0-0-0': BUGZILLA_CVE_FIELD,
        'type0-0-0': 'substring',
        'value0-0-0': cve_id,
    })
    by_title = _bugzilla_query(base_url, {
        'columnlist': 'bug_id,short_desc',
        'product': BUGZILLA_PRODUCT,
        'component': BUGZILLA_SECURITY_COMPONENT,
        'field0-0-0': 'short_desc',
        'type0-0-0': 'substring',
        'value0-0-0': cve_id,
    })
    merged = {ticket['id']: ticket for ticket in by_field + by_title}
    return list(merged.values())


def _package_payload(pkg, bugzilla_tickets=None):
    if not pkg:
        return None
    return {
        'name': pkg.name,
        'summary': pkg.summary,
        'description': pkg.description,
        'url': pkg.url,
        'version': pkg.our_version,
        'bugzilla_tickets': bugzilla_tickets or [],
    }


def build_report_entries(repo_path, fetch_bugzilla=False):
    """Assemble les entrées du rapport : d'abord les alertes confirmées
    (CveMatchLog avec affected_verdict vrai - ce qui, par construction,
    n'arrive que pour une résolution 'exception' ou 'exact'), puis les
    candidats (CveCandidate, dans le même ordre que --list-candidates).
    Chaque entrée est enrichie des détails du CVE (relus depuis le dépôt
    local via cve_file_path, en O(1) par id), du paquet correspondant, et
    (si fetch_bugzilla) des tickets Bugzilla associés. Un CVE dont le
    fichier local est introuvable (dépôt désynchronisé depuis le
    traitement d'origine) est silencieusement omis plutôt que de faire
    échouer tout le rapport."""
    bugzilla_url = getattr(config, 'BUGZILLA_URL', None)
    if fetch_bugzilla and not bugzilla_url:
        logging.warning("config.BUGZILLA_URL non défini : tickets Bugzilla non inclus dans le rapport.")
        fetch_bugzilla = False

    with Session() as session:
        confirmed_rows = session.execute(
            select(CveMatchLog).where(CveMatchLog.affected_verdict == True)  # noqa: E712
        ).scalars().all()
        candidate_rows = session.execute(
            select(CveCandidate).order_by(CveCandidate.score.desc())
        ).scalars().all()
        pkg_by_name_distro = {
            (pkg.name, pkg.distro): pkg for pkg in session.execute(select(Package)).scalars().all()
        }

    cve_json_cache = {}
    bugzilla_by_package_cache = {}
    bugzilla_by_cve_cache = {}

    def get_cve_json(cve_id):
        if cve_id not in cve_json_cache:
            cve_json_cache[cve_id] = load_cve_by_id(repo_path, cve_id)
        return cve_json_cache[cve_id]

    def cve_payload(cve_id, product):
        cve_json = get_cve_json(cve_id)
        if not cve_json:
            return None, None
        affected_record = find_affected_record(cve_json, product)
        payload = {
            'title': get_cve_title(cve_json),
            'vendor': (affected_record or {}).get('vendor', ''),
            'product': product,
            'description': get_cve_description(cve_json),
            'versions': format_affected_versions(affected_record),
            'url': pick_significant_url(cve_json, affected_record),
        }
        return payload, get_published_date(cve_json)

    def get_bugzilla_tickets(cve_id, package_name):
        if not fetch_bugzilla or not package_name:
            return []
        if package_name not in bugzilla_by_package_cache:
            bugzilla_by_package_cache[package_name] = bugzilla_tickets_for_package(bugzilla_url, package_name)
        if cve_id not in bugzilla_by_cve_cache:
            bugzilla_by_cve_cache[cve_id] = bugzilla_tickets_for_cve(bugzilla_url, cve_id)
        merged = {t['id']: t for t in bugzilla_by_package_cache[package_name] + bugzilla_by_cve_cache[cve_id]}
        return list(merged.values())

    entries = []
    seen = set()

    for row in confirmed_rows:
        key = ('confirmed', row.cve_id, row.product, row.distro)
        if key in seen:
            continue
        seen.add(key)
        cve_data, published = cve_payload(row.cve_id, row.product)
        if cve_data is None:
            continue
        entries.append({
            # 'id': f"confirmed:{row.cve_id}:{row.product}:{row.distro}",
            'id': f"confirmed:{row.cve_id}:{row.product}",
            'kind': 'confirmed',
            'cve_id': row.cve_id,
            'product': row.product,
            'distro': row.distro,
            'date_published': published.strftime('%Y-%m-%d') if published else None,
            'score': None,
            'cve': cve_data,
            'package': _package_payload(
                pkg_by_name_distro.get((row.package_name, row.distro)),
                get_bugzilla_tickets(row.cve_id, row.package_name),
            ),
        })

    for row in candidate_rows:
        key = ('candidate', row.cve_id, row.product, row.package_name, row.distro)
        if key in seen:
            continue
        seen.add(key)
        cve_data, published = cve_payload(row.cve_id, row.product)
        if cve_data is None:
            continue
        entries.append({
            'id': f"candidate:{row.cve_id}:{row.product}:{row.package_name}:{row.distro}",
            'kind': 'candidate',
            'cve_id': row.cve_id,
            'product': row.product,
            'distro': row.distro,
            'date_published': published.strftime('%Y-%m-%d') if published else None,
            'score': row.score,
            'cve': cve_data,
            'package': _package_payload(
                pkg_by_name_distro.get((row.package_name, row.distro)),
                get_bugzilla_tickets(row.cve_id, row.package_name),
            ),
        })

    confirmed_entries = [e for e in entries if e['kind'] == 'confirmed']
    candidate_entries = [e for e in entries if e['kind'] == 'candidate']
    confirmed_entries.sort(key=lambda e: e['date_published'] or '', reverse=True)
    # candidate_entries garde l'ordre de la requête (score décroissant)
    return confirmed_entries + candidate_entries


_HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Alertes CVE Mageia</title>
<style>
  :root {
    --bg: #eef0f3;
    --panel: #ffffff;
    --border: #d9dce2;
    --text: #1a1d21;
    --text-muted: #5b6270;
    --confirmed: #a6291f;
    --confirmed-bg: #fbebe9;
    --candidate: #93600c;
    --candidate-bg: #fbf1e0;
    --focus: #2f5fc4;
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.5;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  button { font: inherit; color: inherit; }
  a { color: var(--focus); }
  .layout {
    display: flex;
    height: 100vh;
  }
  .list-pane {
    width: 380px;
    flex: 0 0 380px;
    background: var(--panel);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .list-pane__header {
    padding: 20px 20px 12px;
    border-bottom: 1px solid var(--border);
  }
  .list-pane__header h1 {
    font-size: 16px;
    margin: 0 0 4px;
  }
  .list-pane__count {
    margin: 0;
    color: var(--text-muted);
    font-size: 13px;
  }
  .list-pane__body {
    flex: 1;
    overflow-y: auto;
  }
  .list-group-header {
    position: sticky;
    top: 0;
    background: var(--panel);
    padding: 10px 20px 8px;
    font-size: 13px;
    font-weight: 600;
    border-bottom: 1px solid var(--border);
  }
  .list-empty {
    padding: 14px 20px;
    color: var(--text-muted);
    font-size: 13px;
  }
  .list-row {
    display: flex;
    align-items: baseline;
    gap: 8px;
    width: 100%;
    text-align: left;
    padding: 10px 20px;
    border: 0;
    border-left: 3px solid transparent;
    background: transparent;
    cursor: pointer;
    border-bottom: 1px solid var(--border);
  }
  .list-row:hover { background: #f5f6f8; }
  .list-row:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
  .list-row.is-selected {
    background: #f0f3fb;
    border-left-color: var(--focus);
  }
  .list-row__score {
    flex: 0 0 auto;
    font-size: 11px;
    font-weight: 600;
    color: var(--candidate);
    background: var(--candidate-bg);
    border-radius: 3px;
    padding: 1px 5px;
  }
  .list-row__id {
    flex: 0 0 auto;
    font-size: 12px;
    font-weight: 600;
  }
  .list-row__distro {
    flex: 0 0 auto;
    font-size: 11px;
    color: var(--text-muted);
    background: var(--bg);
    border-radius: 3px;
    padding: 1px 5px;
  }
  .list-row__product {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-muted);
  }
  .list-row__meta {
    flex: 0 0 auto;
    font-size: 12px;
    color: var(--text-muted);
  }
  .detail-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-width: 0;
  }
  .detail-pane__cve, .detail-pane__package {
    overflow-y: auto;
    padding: 28px 40px;
  }
  .detail-pane__cve {
    flex: 1 1 58%;
    border-bottom: 1px solid var(--border);
  }
  .detail-pane__package {
    flex: 1 1 42%;
    background: #f7f8fa;
  }
  .badge {
    display: inline-block;
    font-size: 12px;
    font-weight: 600;
    padding: 3px 9px;
    border-radius: 3px;
    margin-bottom: 14px;
  }
  .badge--confirmed { color: var(--confirmed); background: var(--confirmed-bg); }
  .badge--candidate { color: var(--candidate); background: var(--candidate-bg); }
  .cve-id {
    margin: 0 0 4px;
    font-size: 13px;
    color: var(--text-muted);
  }
  .detail-pane h2 {
    margin: 0 0 16px;
    font-size: 21px;
    font-weight: 600;
    max-width: 60ch;
  }
  .meta-list {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 16px;
    margin: 0 0 18px;
    font-size: 13px;
  }
  .meta-list dt { color: var(--text-muted); }
  .meta-list dd { margin: 0; }
  .description {
    max-width: 68ch;
    margin: 0 0 20px;
    line-height: 1.65;
  }
  .detail-pane h3 {
    font-size: 13px;
    text-transform: none;
    margin: 0 0 8px;
    color: var(--text-muted);
    font-weight: 600;
  }
  .version-list {
    margin: 0 0 20px;
    padding-left: 18px;
  }
  .version-list li {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
    margin-bottom: 3px;
  }
  .source-link {
    display: inline-block;
    font-size: 13px;
    word-break: break-all;
  }
  .package-name {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 17px;
    font-weight: 600;
    margin: 0 0 6px;
  }
  .package-version {
    font-size: 13px;
    color: var(--text-muted);
    margin: 0 0 14px;
  }
  .package-summary {
    font-weight: 600;
    margin: 0 0 10px;
  }
  .bugzilla-header {
    margin-top: 20px;
  }
  .bugzilla-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .bugzilla-list li {
    margin-bottom: 6px;
  }
  .bugzilla-list a {
    font-size: 13px;
  }
  .bugzilla-id {
    color: var(--text-muted);
    margin-right: 4px;
  }
  .empty {
    color: var(--text-muted);
    padding: 40px;
  }
  @media (max-width: 760px) {
    .layout { flex-direction: column; }
    .list-pane { width: 100%; flex: 0 0 40%; border-right: 0; border-bottom: 1px solid var(--border); }
    .detail-pane__cve, .detail-pane__package { padding: 20px; }
  }
</style>
</head>
<body>
  <div class="layout">
    <aside class="list-pane">
      <div class="list-pane__header">
        <h1>Alertes CVE</h1>
        <p class="list-pane__count" id="count"></p>
      </div>
      <div class="list-pane__body" id="list"></div>
    </aside>
    <main class="detail-pane">
      <section class="detail-pane__cve" id="cve-detail">
        <p class="empty">Sélectionnez une entrée à gauche.</p>
      </section>
      <section class="detail-pane__package" id="package-detail"></section>
    </main>
  </div>

  <script type="application/json" id="report-data">__REPORT_DATA__</script>
  <script>
    const data = JSON.parse(document.getElementById('report-data').textContent);
    const listEl = document.getElementById('list');
    const countEl = document.getElementById('count');
    const cveDetailEl = document.getElementById('cve-detail');
    const packageDetailEl = document.getElementById('package-detail');

    function addGroup(title, items, emptyText) {
      const header = document.createElement('div');
      header.className = 'list-group-header';
      header.textContent = title + ' (' + items.length + ')';
      listEl.appendChild(header);
      if (items.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'list-empty';
        empty.textContent = emptyText;
        listEl.appendChild(empty);
        return;
      }
      items.forEach(function (entry) {
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'list-row';
        row.dataset.id = entry.id;
        if (entry.kind === 'candidate' && entry.score != null) {
          const scoreEl = document.createElement('span');
          scoreEl.className = 'list-row__score';
          scoreEl.textContent = Math.round(entry.score);
          row.appendChild(scoreEl);
        }
        const idEl = document.createElement('span');
        idEl.className = 'list-row__id mono';
        idEl.textContent = entry.cve_id;
        row.appendChild(idEl);
        if (entry.distro) {
          const distroEl = document.createElement('span');
          distroEl.className = 'list-row__distro mono';
          distroEl.textContent = 'Mga' + entry.distro;
          row.appendChild(distroEl);
        }
        const productEl = document.createElement('span');
        productEl.className = 'list-row__product';
        productEl.textContent = entry.product;
        row.appendChild(productEl);
        const metaEl = document.createElement('span');
        metaEl.className = 'list-row__meta';
        metaEl.textContent = entry.date_published || '';
        row.appendChild(metaEl);
        row.addEventListener('click', function () { selectEntry(entry.id); });
        listEl.appendChild(row);
      });
    }

    function renderList() {
      const confirmed = data.filter(function (e) { return e.kind === 'confirmed'; });
      const candidates = data.filter(function (e) { return e.kind === 'candidate'; });
      countEl.textContent = confirmed.length + ' alerte(s) confirmée(s), ' + candidates.length + ' candidat(s) à revoir.';
      listEl.innerHTML = '';
      addGroup('Alertes confirmées', confirmed, 'Aucune alerte confirmée pour le moment.');
      addGroup('Candidats à revoir', candidates, 'Aucun candidat en attente.');
    }

    function addRow(container, label, value) {
      if (!value) return;
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = value;
      container.appendChild(dt);
      container.appendChild(dd);
    }

    function renderCveDetail(entry) {
      cveDetailEl.innerHTML = '';
      const badge = document.createElement('span');
      badge.className = 'badge badge--' + entry.kind;
      badge.textContent = entry.kind === 'confirmed'
        ? 'Alerte confirmée'
        : 'Candidat à vérifier' + (entry.score != null ? ' — score ' + Math.round(entry.score) : '');
      cveDetailEl.appendChild(badge);

      const idLine = document.createElement('p');
      idLine.className = 'cve-id mono';
      idLine.textContent = entry.cve_id;
      cveDetailEl.appendChild(idLine);

      const title = document.createElement('h2');
      title.textContent = entry.cve.title || entry.product;
      cveDetailEl.appendChild(title);

      const meta = document.createElement('dl');
      meta.className = 'meta-list';
      addRow(meta, 'Éditeur', entry.cve.vendor);
      addRow(meta, 'Produit', entry.cve.product);
      cveDetailEl.appendChild(meta);

      if (entry.cve.description) {
        const desc = document.createElement('p');
        desc.className = 'description';
        desc.textContent = entry.cve.description;
        cveDetailEl.appendChild(desc);
      }

      if (entry.cve.versions && entry.cve.versions.length) {
        const h3 = document.createElement('h3');
        h3.textContent = 'Versions affectées';
        cveDetailEl.appendChild(h3);
        const ul = document.createElement('ul');
        ul.className = 'version-list';
        entry.cve.versions.forEach(function (line) {
          const li = document.createElement('li');
          li.textContent = line;
          ul.appendChild(li);
        });
        cveDetailEl.appendChild(ul);
      }

      if (entry.cve.url) {
        const link = document.createElement('a');
        link.href = entry.cve.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.className = 'source-link';
        link.textContent = entry.cve.url;
        cveDetailEl.appendChild(link);
      }
    }

    function renderPackageDetail(entry) {
      packageDetailEl.innerHTML = '';
      const h3 = document.createElement('h3');
      h3.textContent = 'Paquet';
      packageDetailEl.appendChild(h3);

      const pkg = entry.package;
      if (!pkg) {
        const p = document.createElement('p');
        p.className = 'empty';
        p.style.padding = '0';
        p.textContent = "Paquet introuvable dans la base (a peut-être été retiré depuis).";
        packageDetailEl.appendChild(p);
        return;
      }

      const name = document.createElement('p');
      name.className = 'package-name mono';
      name.textContent = pkg.name;
      packageDetailEl.appendChild(name);

      if (pkg.version) {
        const version = document.createElement('p');
        version.className = 'package-version';
        const distroTxt = entry.distro ? ' (Mageia ' + entry.distro + ')' : '';
        version.textContent = 'Version installée' + distroTxt + ' : ' + pkg.version;
        packageDetailEl.appendChild(version);
      }
      if (pkg.summary) {
        const summary = document.createElement('p');
        summary.className = 'package-summary';
        summary.textContent = pkg.summary;
        packageDetailEl.appendChild(summary);
      }
      if (pkg.description) {
        const desc = document.createElement('p');
        desc.className = 'description';
        desc.textContent = pkg.description;
        packageDetailEl.appendChild(desc);
      }
      if (pkg.url) {
        const link = document.createElement('a');
        link.href = pkg.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.className = 'source-link';
        link.textContent = pkg.url;
        packageDetailEl.appendChild(link);
      }

      if (pkg.bugzilla_tickets && pkg.bugzilla_tickets.length) {
        const ticketsHeader = document.createElement('h3');
        ticketsHeader.className = 'bugzilla-header';
        ticketsHeader.textContent = 'Tickets Bugzilla';
        packageDetailEl.appendChild(ticketsHeader);
        const ul = document.createElement('ul');
        ul.className = 'bugzilla-list';
        pkg.bugzilla_tickets.forEach(function (ticket) {
          const li = document.createElement('li');
          const link = document.createElement('a');
          link.href = ticket.url;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          const idSpan = document.createElement('span');
          idSpan.className = 'mono bugzilla-id';
          idSpan.textContent = '#' + ticket.id;
          link.appendChild(idSpan);
          link.appendChild(document.createTextNode(' ' + (ticket.title || '(sans titre)')));
          li.appendChild(link);
          ul.appendChild(li);
        });
        packageDetailEl.appendChild(ul);
      }
    }

    function selectEntry(id) {
      const entry = data.find(function (e) { return e.id === id; });
      if (!entry) return;
      document.querySelectorAll('.list-row').forEach(function (row) {
        row.classList.toggle('is-selected', row.dataset.id === id);
      });
      renderCveDetail(entry);
      renderPackageDetail(entry);
    }

    renderList();
    if (data.length) {
      selectEntry(data[0].id);
    } else {
      cveDetailEl.innerHTML = '<p class="empty">Aucune donnée. Lancez un traitement (--update-packages) puis régénérez ce rapport.</p>';
    }
  </script>
</body>
</html>
"""


def render_html_report(entries):
    payload = json.dumps(entries, ensure_ascii=False)
    # Se prémunir d'un texte de CVE contenant littéralement "</script>",
    # qui casserait sinon le bloc JSON intégré.
    payload = payload.replace('</', '<\\/')
    return _HTML_REPORT_TEMPLATE.replace('__REPORT_DATA__', payload)


def export_html_report(repo_path, output_path, fetch_bugzilla=False):
    """Génère le rapport HTML interactif (liste + détail) dans
    output_path, à partir de l'état actuel de la base (alertes
    confirmées et candidats). Ne resynchronise rien : relancez le
    traitement normal ou --rematch avant si besoin de données à jour."""
    entries = build_report_entries(repo_path, fetch_bugzilla=fetch_bugzilla)
    html = render_html_report(entries)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path, entries



    """Affiche les correspondances product -> paquet non encore tranchées,
    triées par score décroissant, pour une revue manuelle."""
    with Session() as session:
        rows = session.execute(
            select(CveCandidate).order_by(CveCandidate.score.desc())
        ).scalars().all()

    if not rows:
        print("Aucun candidat en attente de revue.")
        return rows

    print(f"{len(rows)} candidat(s) en attente de revue :")
    for row in rows:
        verdict = {True: "affecté", False: "non affecté", None: "indéterminé"}[row.affected]
        via = []
        if row.name_score:
            via.append(f"nom={row.name_score}")
        if row.url_score:
            via.append(f"url={row.url_score}")
            if row.matched_url:
                via.append(row.matched_url)
        print(
            f" - {row.cve_id} : '{row.product}' -> {row.package_name} "
            f"(score {row.score}, {', '.join(via)}, {verdict})"
        )
    return rows


def confirm_candidate(cve_id, package_name, exceptions_path):
    """Valide un candidat : ajoute son 'product' à exceptions.csv comme
    correspondance définitive vers package_name, puis retire de
    cve_candidates toutes les entrées portant sur ce même product (elles
    seront résolues directement par l'exception dès la prochaine
    exécution)."""
    with Session() as session:
        row = session.execute(
            select(CveCandidate).where(
                CveCandidate.cve_id == cve_id,
                CveCandidate.package_name == package_name,
            )
        ).scalars().first()

        if not row:
            print(f"Aucun candidat trouvé pour {cve_id} / {package_name}.")
            return

        product = row.product
        exceptions = load_exceptions(exceptions_path)
        exceptions[product] = package_name

        with open(exceptions_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for src, dst in sorted(exceptions.items()):
                writer.writerow([src, dst])

        stmt = delete(CveCandidate).where(CveCandidate.product == product)
        session.execute(stmt)
        session.commit()

    print(f"Exception ajoutée : '{product}' -> {package_name} (dans {exceptions_path}).")


def check_cves(repo_path=None, repo_url=None, exceptions_path=None, stranger_path=None, initial_days=None):
    repo_path = repo_path or getattr(
        config, 'CVE_REPO_PATH', os.path.join(config.EXTERNAL_PATH, 'cvelistV5')
    )
    repo_url = repo_url or getattr(
        config, 'CVE_REPO_URL', 'git@github.com:CVEProject/cvelistV5.git'
    )
    exceptions_path = exceptions_path or getattr(
        config, 'CVE_EXCEPTIONS_PATH', os.path.join(config.EXTERNAL_PATH, 'exceptions.csv')
    )
    strangers_path = exceptions_path or getattr(
        config, 'CVE_STARNGERS_PATH', os.path.join(config.EXTERNAL_PATH, 'strangers.csv')
    )
    initial_days = initial_days if initial_days is not None else getattr(
        config, 'CVE_INITIAL_DAYS', 30
    )

    sync_repo(repo_path, repo_url)
    checked_count, alerts, candidate_count = process_new_cves(repo_path, exceptions_path, strangers_path, initial_days)

    print(f"{checked_count} nouvelle(s) alerte(s) CVE examinée(s).")
    if alerts:
        print(f"{len(alerts)} paquet(s) potentiellement affecté(s) :")
        for a in alerts:
            print(f" - {a['cve_id']} : {a['package']} [Mageia {a['distro']}] (version installée {a['our_version']})")
    else:
        print("Aucun paquet de la base ne semble affecté.")

    if candidate_count:
        print(
            f"{candidate_count} correspondance(s) incertaine(s) product/paquet à revoir "
            f"(voir --list-candidates)."
        )

    return checked_count, alerts, candidate_count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--update-packages', action='store_true',
        help="Mettre à jour la base des paquets depuis les SRPMS avant la vérification CVE",
    )
    parser.add_argument('--repo-path', default=None, help="Chemin du clone local de cvelistV5")
    parser.add_argument('--repo-url', default=None, help="URL du dépôt git cvelistV5")
    parser.add_argument('--exceptions', default=None, help="Chemin du fichier exceptions.csv")
    parser.add_argument(
        '--initial-days', type=int, default=None,
        help="Nombre de jours à considérer lors du tout premier traitement (défaut : 30)",
    )
    parser.add_argument(
        '--list-candidates', action='store_true',
        help="Afficher les correspondances product/paquet incertaines en attente de revue, sans rien synchroniser",
    )
    parser.add_argument(
        '--match-log-summary', action='store_true',
        help="Diagnostiquer les rapprochements product/paquet (répartition, quasi-ratés, échecs du contrôle de version), sans rien synchroniser",
    )
    parser.add_argument(
        '--confirm', nargs=2, metavar=('CVE_ID', 'PACKAGE_NAME'), default=None,
        help="Valider un candidat proposé : ajoute son product à exceptions.csv comme correspondance définitive vers PACKAGE_NAME",
    )
    parser.add_argument(
        '--rematch', action='store_true',
        help="Rejouer le rapprochement product/paquet sur les CVE déjà examinés (sans resynchroniser ni retoucher processed_cves), utile après une évolution de la logique de rapprochement ou de exceptions.csv",
    )
    parser.add_argument(
        '--export-html', nargs='?', const='__DEFAULT__', default=None, metavar='PATH',
        help="Générer un rapport HTML interactif (liste des alertes confirmées puis des candidats, détail CVE/paquet) dans PATH (défaut : cve_report.html dans le répertoire de données)",
    )
    parser.add_argument(
        '--fetch-bugzilla', action='store_true',
        help="Avec --export-html : interroger aussi Bugzilla pour les tickets liés pendant la génération (une requête par paquet/CVE distinct, donc lent). Par défaut, le rapport HTML n'inclut pas les tickets Bugzilla - utilisez plutôt cve_ui.py (interface PyQt6), qui ne les recherche qu'à la sélection d'une entrée",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.list_candidates:
        list_pending_candidates()
        raise SystemExit(0)

    if args.match_log_summary:
        summarize_match_log()
        raise SystemExit(0)

    if args.export_html is not None:
        repo_path = args.repo_path or getattr(
            config, 'CVE_REPO_PATH', os.path.join(config.EXTERNAL_PATH, 'cvelistV5')
        )
        output_path = args.export_html
        if output_path == '__DEFAULT__':
            output_path = os.path.join(config.EXTERNAL_PATH, 'cve_report.html')
        path, entries = export_html_report(repo_path, output_path, fetch_bugzilla=args.fetch_bugzilla)
        print(f"Rapport généré : {path} ({len(entries)} entrée(s)).")
        raise SystemExit(0)

    if args.rematch:
        repo_path = args.repo_path or getattr(
            config, 'CVE_REPO_PATH', os.path.join(config.EXTERNAL_PATH, 'cvelistV5')
        )
        exceptions_path = args.exceptions or getattr(
            config, 'CVE_EXCEPTIONS_PATH', os.path.join(config.EXTERNAL_PATH, 'exceptions.csv')
        )
        strangers_path = args.exceptions or getattr(
            config, 'CVE_STRANGERS_PATH', os.path.join(config.EXTERNAL_PATH, 'strangers.csv')
        )
        rematched_count, alerts, candidate_count = rematch_all(repo_path, exceptions_path, strangers_path)
        print(f"{rematched_count} CVE rejoué(s).")
        if alerts:
            print(f"{len(alerts)} paquet(s) potentiellement affecté(s) :")
            for a in alerts:
                print(f" - {a['cve_id']} : {a['package']} [Mageia {a['distro']}] (version installée {a['our_version']})")
        if candidate_count:
            print(f"{candidate_count} correspondance(s) incertaine(s) product/paquet à revoir (voir --list-candidates).")
        raise SystemExit(0)

    if args.confirm:
        exceptions_path = args.exceptions or getattr(
            config, 'CVE_EXCEPTIONS_PATH', os.path.join(config.EXTERNAL_PATH, 'exceptions.csv')
        )
        confirm_candidate(args.confirm[0], args.confirm[1], exceptions_path)
        raise SystemExit(0)

    if args.update_packages:
        update_packages_db(force=True)

    check_cves(
        repo_path=args.repo_path,
        repo_url=args.repo_url,
        exceptions_path=args.exceptions,
        initial_days=args.initial_days,
    )
