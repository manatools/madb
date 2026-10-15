# Notice d'utilisation — cve\_check.py et cve\_ui.py

Outils de veille de sécurité pour les paquets Mageia : rapprochement automatique entre les CVE publiés et les paquets de la distribution, sur trois versions suivies en parallèle.

## Vue d'ensemble

Les deux outils partagent la même base de données SQLite (`packages.db`, dans `config.EXTERNAL_PATH`) et le même clone local du dépôt CVE (`cvelistV5`).

- **`cve_check.py`** : outil en ligne de commande. C'est lui qui fait tout le travail de fond — synchronise le dépôt CVE, met à jour la liste des paquets, calcule les rapprochements CVE ↔ paquet, détecte les versions affectées. Conçu pour tourner périodiquement (cron, tâche planifiée).
- **`cve_ui.py`** : interface graphique PyQt6. Ne fait aucun calcul lui-même — il se contente de lire l'état déjà calculé par `cve_check.py` et de le présenter pour la revue humaine, avec un lien direct vers les tickets Bugzilla associés.

En pratique : on lance `cve_check.py` régulièrement pour tenir la base à jour, et on ouvre `cve_ui.py` quand on veut consulter ou trier les résultats.

## Prérequis

### Dépendances Python

```
pip install semver rapidfuzz sqlalchemy --break-system-packages
pip install PyQt6 --break-system-packages   # pour cve_ui.py uniquement
```

### Fichier de configuration (`madb/config.py`)

Variables **obligatoires**, utilisées directement sans valeur par défaut :

| Variable | Rôle |
| --- | --- |
| `DATA_PATH` | chemin des données dnf5/madb (passé à `Dnf5MadbBase`) |
| `EXTERNAL_PATH` | répertoire de travail : y sont stockés `packages.db`, le clone `cvelistV5/` et `exceptions.csv` par défaut |
| `DEV_NAME` | nom du dépôt de la version de développement (ex. `"cauldron"`) |
| `TOP_RELEASE` | numéro entier de la dernière version stable (ex. `10`) |

Variables **optionnelles** (valeur par défaut si absentes) :

| Variable | Défaut si absente |
| --- | --- |
| `CVE_REPO_PATH` | `EXTERNAL_PATH/cvelistV5` |
| `CVE_REPO_URL` | `git@github.com:CVEProject/cvelistV5.git` |
| `CVE_EXCEPTIONS_PATH` | `EXTERNAL_PATH/exceptions.csv` |
| `CVE_INITIAL_DAYS` | `30` |
| `BUGZILLA_URL` | tickets Bugzilla désactivés si absente |

### Les trois versions suivies

Chaque paquet est recherché dans trois versions de la distribution, identifiées par un numéro :

- **Développement** (dépôt `DEV_NAME`, ex. `cauldron`) → numéro `TOP_RELEASE + 1`
- **Dernière stable** → numéro `TOP_RELEASE`
- **Stable précédente** → numéro `TOP_RELEASE − 1`

Un même paquet peut donc apparaître jusqu'à trois fois dans la base, avec une version installée différente selon la distribution — et être affecté par un CVE dans l'une et pas dans l'autre.

### Clé d'accès au Bugzilla

L'interface graphique permet de soumettre des requêtes au Bugzilla. Pour cela, il est nécessaire de créer une clé d'API dans le compte de l'utilisateur sur le Bugzilla, puis d'exporter celle-ci en variable d'environnement.

User preferences - Onglet "API Keys" - "Generate a new API key with optional description"

La commande est alors :
```
export BUGZILLA_API_KEY=<clé utilisateur>
```

---

## cve\_check.py — outil en ligne de commande

### Premier lancement

```
python cve_check.py --update-packages
```

Cette première exécution :

1. clone (ou met à jour) le dépôt `cvelistV5` ;
2. peuple la base des paquets pour les trois versions suivies ;
3. examine les CVE publiés dans les `CVE_INITIAL_DAYS` derniers jours (30 par défaut) — pas tout l'historique, pour rester rapide.

### Lancements suivants

```
python cve_check.py
```

Sans `--update-packages`, les paquets ne sont pas réactualisés (plus rapide) ; seuls les nouveaux CVE publiés depuis le dernier passage sont examinés. Ajoutez `--update-packages` périodiquement (par exemple une fois par jour) pour tenir les versions installées à jour.

À chaque exécution, le résumé affiché distingue :

- les **alertes confirmées** : un paquet connu, dont la version installée est dans la plage affectée par le CVE ;
- les **candidats** : une correspondance product → paquet incertaine (par similarité de nom et/ou d'URL), à trancher manuellement.

### Résultats incertains : exceptions.csv

Quand le nom du `product` cité dans un CVE ne correspond pas exactement au nom du paquet Mageia, l'outil propose des candidats plutôt que de deviner. Le fichier `exceptions.csv` (deux colonnes : `product,nom_du_paquet`) permet de figer une correspondance une fois pour toutes.

```
python cve_check.py --list-candidates
```

Affiche les candidats en attente, triés par score de confiance décroissant.

```
python cve_check.py --confirm CVE-2026-12345 nom_du_paquet
```

Valide un candidat : ajoute la correspondance à `exceptions.csv` et retire les candidats devenus inutiles pour ce `product`.

### Diagnostiquer un rapprochement qui semble manquant

```
python cve_check.py --match-log-summary
```

Donne la répartition des résolutions (exception / nom exact / candidat approché / aucune correspondance), les meilleurs scores manqués sous le seuil, et les correspondances trouvées mais dont le contrôle de version n'a pas conclu à « affecté ». Utile pour comprendre pourquoi une alerte attendue n'apparaît pas.

### Rejouer le rapprochement sans tout retraiter

```
python cve_check.py --rematch
```

Recalcule les correspondances pour les CVE déjà examinés (sans resynchroniser le dépôt ni retoucher la fenêtre initiale). À utiliser après avoir enrichi `exceptions.csv`, ou après une mise à jour du script qui change la logique de rapprochement.

### Générer un rapport HTML autonome

```
python cve_check.py --export-html [chemin.html]
python cve_check.py --export-html --fetch-bugzilla
```

Produit une page HTML consultable hors ligne (liste des alertes confirmées puis des candidats, détail CVE et paquet). `--fetch-bugzilla` inclut aussi les tickets Bugzilla liés, mais interroge Bugzilla pour chaque paquet/CVE distinct pendant la génération — nettement plus lent. Sans cette option, le rapport se génère vite mais sans les tickets ; pour les consulter confortablement, préférer `cve_ui.py`, qui ne les recherche qu'à la demande.

### Référence des options

| Option | Effet |
| --- | --- |
| `--update-packages` | Réactualise les paquets des trois distributions avant la vérification |
| `--repo-path CHEMIN` | Chemin du clone local `cvelistV5` (remplace `CVE_REPO_PATH`) |
| `--repo-url URL` | URL du dépôt CVE (remplace `CVE_REPO_URL`) |
| `--exceptions CHEMIN` | Chemin de `exceptions.csv` (remplace `CVE_EXCEPTIONS_PATH`) |
| `--initial-days N` | Fenêtre du tout premier traitement (défaut 30) |
| `--list-candidates` | Liste les candidats en attente, sans rien synchroniser |
| `--match-log-summary` | Diagnostic des rapprochements, sans rien synchroniser |
| `--confirm CVE PAQUET` | Valide un candidat dans `exceptions.csv` |
| `--rematch` | Rejoue le rapprochement sur les CVE déjà examinés |
| `--export-html [CHEMIN]` | Génère le rapport HTML |
| `--fetch-bugzilla` | Avec `--export-html` : inclut les tickets Bugzilla (lent) |

### Workflow périodique conseillé

```
# une fois par jour, par exemple via cron
python cve_check.py --update-packages

# de temps en temps, après avoir traité des candidats
python cve_check.py --list-candidates
python cve_check.py --confirm CVE-xxxx-yyyy nom_du_paquet
python cve_check.py --rematch
```

---

## cve\_ui.py — interface graphique

### Lancement

```
python cve_ui.py
python cve_ui.py --repo-path /chemin/vers/cvelistV5   # si différent de la config
```

L'interface lit l'état actuel de la base **telle que laissée par le dernier passage de `cve_check.py`** — elle ne synchronise ni ne recalcule rien. Pensez à lancer `cve_check.py` avant d'ouvrir l'interface si vous voulez des données fraîches.

### Organisation de l'écran

- **Colonne de gauche** : une liste à deux groupes, « Alertes confirmées » puis « Candidats à revoir » (avec leur score). Une seule ligne par CVE et par produit concerné — un même CVE affectant plusieurs distributions n'apparaît qu'une fois ici.
- **Panneau supérieur droit** : détail du CVE sélectionné — titre, éditeur, produit, description, plages de versions affectées, lien vers la source.
- **Panneau inférieur droit** : le ou les paquets correspondants, avec **une ligne par distribution** où le paquet existe (numéro de version, version installée) puisque le statut peut différer d'une distribution à l'autre. Les tickets Bugzilla liés (champ *Source RPM* ou *CVE*, ou mention dans le titre) s'affichent en dessous.

### Tickets Bugzilla à la demande

Contrairement à `--export-html --fetch-bugzilla`, l'interface ne recherche les tickets Bugzilla qu'**au moment où vous sélectionnez une entrée**, dans un thread séparé qui ne bloque pas l'affichage (« Recherche en cours… » le temps de la requête). Si `BUGZILLA_URL` n'est pas défini dans `config.py`, cette partie est simplement désactivée (message dans la barre d'état).

---

## Points d'attention

- **`exceptions.csv` se construit avec le temps.** Les premiers passages produisent davantage de candidats ; la liste se réduit au fil des `--confirm`. Pensez à relancer `--rematch` après une session de revue pour que les alertes reflètent les dernières décisions.
- **Un candidat n'est jamais une alerte.** Tant qu'une correspondance n'est pas confirmée (exception explicite ou nom identique corroboré), elle n'apparaît que dans les candidats — même si elle semble évidente.
- **`cve_ui.py` ne modifie rien.** La revue et la confirmation des candidats se font côté `cve_check.py` (`--confirm`) ; l'interface graphique est un outil de consultation.
