#!/usr/bin/env python3
"""
Interface graphique PyQt6 pour consulter les alertes CVE et les candidats
générés par cve_check.py.

Réutilise directement les fonctions de cve_check.py (build_report_entries,
bugzilla_tickets_for_package, bugzilla_tickets_for_cve...) plutôt que de
dupliquer la logique. Contrairement à --export-html, les tickets Bugzilla
ne sont recherchés qu'au moment où l'utilisateur sélectionne une entrée
(dans un thread séparé, pour ne jamais geler l'interface), pas pour
toutes les entrées au démarrage.
"""
import argparse
import html
import os
import sys
import re
import requests
from subprocess import run as sprun

from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal, QTimer, QRectF
from PyQt6.QtGui import (
    QFont,
    QDesktopServices,
    QAction,
    QPainter,
    QColor,
    QPen,
)
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QLabel,
    QLineEdit,
    QMainWindow,
    QDialog,
    QSplitter,
    QStatusBar,
    QTextBrowser,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
    QVBoxLayout,
    QGridLayout,
    QPushButton,
    QDialogButtonBox
)

import cve_check as cc
import madb.config as config


def esc(value):
    """Échappement HTML sûr pour l'insertion dans un QTextBrowser, y
    compris en contexte attribut (href="...") : les descriptions de CVE
    ou les URLs peuvent contenir '&', '<', '"'..."""
    return html.escape(str(value) if value is not None else '', quote=True)


class UpdateWorker(QObject):
    """Exécuté dans un QThread séparé : une mise à jour peut
    prendre plusieurs minutes, elle ne doit jamais geler l'UI."""
    finished = pyqtSignal(str, list)
    failed = pyqtSignal(str, str)

    def __init__(self, repo_path):
        super().__init__()
        self.repo_path = repo_path

    def run(self):
        cc.update_packages_db(force=True)
        cc.check_cves(repo_path=self.repo_path)


class BugzillaWorker(QObject):
    """Exécuté dans un QThread séparé : une recherche Bugzilla peut
    prendre plusieurs secondes, elle ne doit jamais geler l'UI."""
    finished = pyqtSignal(str, list)
    failed = pyqtSignal(str, str)

    def __init__(self, bugzilla_url, entry_id, cve_id, package_name):
        super().__init__()
        self.bugzilla_url = bugzilla_url
        self.entry_id = entry_id
        self.cve_id = cve_id
        self.package_name = package_name

    def run(self):
        try:
            by_package = (
                cc.bugzilla_tickets_for_package(self.bugzilla_url, self.package_name)
                if self.package_name else []
            )
            by_cve = cc.bugzilla_tickets_for_cve(self.bugzilla_url, self.cve_id)
            merged = {t['id']: t for t in by_package + by_cve}
            self.finished.emit(self.entry_id, list(merged.values()))
        except Exception as exc:  # défensif : ne doit jamais faire planter le thread
            self.failed.emit(self.entry_id, str(exc))


class LoadingWheel(QWidget):
    def __init__(self, parent=None, color=QColor("#3498db"), speed=60):
        super().__init__(parent)
        self.color = color
        self.angle = 0
        self.counter = 0

        # Nombre de lignes/bâtonnets de la roue
        self.lines_count = 12
        # Timer pour animer la roue (60 ms par étape par défaut)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.rotate)
        # Fixe une taille minimale par défaut
        self.setMinimumSize(40, 40)

    def start(self):
        """Démarre l'animation"""
        self.timer.start(60)
        self.show()

    def stop(self):
        """Arrête l'animation"""
        self.timer.stop()
        self.hide()

    def rotate(self):
        # Fait avancer l'index de surbrillance
        self.counter = (self.counter + 1) % self.lines_count
        self.update() # Force le widget à se redessiner

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # On se place au centre du widget
        width = self.width()
        height = self.height()
        side = min(width, height)
        painter.translate(width / 2, height / 2)

        # Calcul des dimensions des batonnets proportionnellement à la taille du widget
        radius = (side / 2) * 0.8
        line_length = radius * 0.4
        line_width = side / 15

        pen = QPen()
        pen.setWidthF(line_width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap) # Bords arrondis

        # Dessin des 12 segments circulaires
        for i in range(self.lines_count):
            # Calcul de l'opacité (effet de dégradé/traînée)
            # La ligne active est la plus opaque, les précédentes s'estompent
            opacity = int(255 * ((i + self.counter) % self.lines_count) / self.lines_count)

            current_color = QColor(self.color)
            current_color.setAlpha(max(30, opacity)) # Opacité min à 30 pour la visibilité
            pen.setColor(current_color)
            painter.setPen(pen)

            # Dessin de la ligne verticale
            painter.drawLine(0, int(radius - line_length), 0, int(radius))

            # Rotation pour la ligne suivante (360° / 12 = 30°)
            painter.rotate(360.0 / self.lines_count)

        painter.end()


# --- Fenêtre de mise à jour ---
class UpdateWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mise à jour des données CVEs et des paquets")
        self.resize(300, 200)

        layout = QVBoxLayout(self)

        # Création de notre roue animée personnalisée
        self.spinner = LoadingWheel(self, color=QColor("#2ecc71"))
        layout.addWidget(self.spinner, alignment=Qt.AlignmentFlag.AlignCenter)

        # Boutons de contrôle
        self.btn_start = QPushButton("Démarrer", self)
        self.btn_start.clicked.connect(self.start)
        layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("Fermer", self)
        self.btn_stop.clicked.connect(self.spinner.stop)
        layout.addWidget(self.btn_stop)

    def start(self):
        # Démarre l'animation d'entrée
        self.spinner.start()


class TicketSubmission(QDialog):
    def __init__(self, summary="", description="", cve="", parent=None):
        super().__init__(parent)
        layout1 = QVBoxLayout(self)
        self.setWindowTitle("Créer un ticket")
        self.setMinimumWidth(800)
        layout = QGridLayout()
        layout.addWidget(QLabel("Version"), 0, 0)
        self.version_field = QComboBox()
        self.version_field.addItems(["Cauldron", "10", "9"])
        layout.addWidget(self.version_field, 0, 1)
        layout.addWidget(QLabel("Summary"), 1, 0)
        self.summary_field = QLineEdit(summary)
        layout.addWidget(self.summary_field, 1, 1)
        layout.addWidget(QLabel("Description"), 2, 0)
        self.description_field = QTextEdit(description)
        layout.addWidget(self.description_field, 2, 1)
        layout.addWidget(QLabel("CVE"), 3, 0)
        self.cve_field = QLineEdit(cve)
        layout.addWidget(self.cve_field, 3, 1)
        layout1.addLayout(layout)

        boutons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Ok
        )
        boutons.button(QDialogButtonBox.StandardButton.Ok).setText("Soumettre")
        boutons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annuler")

        boutons.accepted.connect(self.accept)
        boutons.rejected.connect(self.reject)
        layout1.addWidget(boutons)

    def payload(self):
        payload = {
            "product": "Mageia",
            "component": "Security",
            "version": self.version_field.currentText(),
            "summary": self.summary_field.text(),
            "description": self.description_field.toPlainText(),
            "cf_cve": self.cve_field.text(),
            }
        return payload


class MainWindow(QMainWindow):
    def __init__(self, bugzilla_url, repo_path):
        super().__init__()

        # fetch_bugzilla=False : chargement initial rapide, les tickets sont
        # recherchés à la demande (voir BugzillaWorker) plutôt que pour
        # toutes les entrées au démarrage.
        self.ordered_entries = cc.build_report_entries(repo_path, fetch_bugzilla=False)

        self.entries_by_id = {entry['id']: entry for entry in self.ordered_entries}
        self.bugzilla_url = bugzilla_url
        self.repo_path = repo_path
        self.current_entry_id = None
        self.bugzilla_thread = None
        self.bugzilla_worker = None

        self.setWindowTitle("Alertes CVE Mageia")
        self.resize(1280, 820)
        # Création de la barre de menu
        menu_bar = self.menuBar()

        update_menu = menu_bar.addMenu("&Base")
        # Ajout de l'action au menu Fichier
        update_action = QAction("&Mettre les données à jour", self)
        update_action.setStatusTip("Concerne les CVEs et les paquets")
        update_action.triggered.connect(self._update)
        update_menu.addAction(update_action)
        # Création d'une action "Quitter"
        exit_action = QAction("&Quitter", self)
        exit_action.setShortcut("Ctrl+Q")  # Raccourci clavier
        exit_action.setStatusTip("Quitter l'application")  # Texte d'aide
        exit_action.triggered.connect(self.close)  # Connexion au signal de fermeture
        update_menu.addAction(exit_action)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setMinimumWidth(340)
        self.tree.setMaximumWidth(460)
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        self._populate_tree()

        self.cve_view = QTextBrowser()
        self.cve_view.setOpenExternalLinks(True)
        self.package_view = QTextBrowser()
        self.package_view.setOpenExternalLinks(False)
        self.package_view.anchorClicked.connect(self._manage_click)

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.addWidget(self.cve_view)
        right_splitter.addWidget(self.package_view)
        right_splitter.setSizes([480, 340])

        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.addWidget(self.tree)
        main_splitter.addWidget(right_splitter)
        main_splitter.setSizes([380, 900])
        self.setCentralWidget(main_splitter)

        self.setStatusBar(QStatusBar())
        if not self.bugzilla_url:
            self.statusBar().showMessage(
                "config.BUGZILLA_URL non défini : tickets Bugzilla désactivés.")

        if self.ordered_entries:
            first_item = self.tree.topLevelItem(0).child(0) if self.tree.topLevelItem(0).childCount() else \
                (self.tree.topLevelItem(1).child(0) if self.tree.topLevelItem(1).childCount() else None)
            if first_item:
                first_item.setSelected(True)
        else:
            self.cve_view.setHtml(
                "<p><i>Aucune donnée. Lancez un traitement (--update-packages) "
                "côté cve_check.py puis relancez cette interface.</i></p>")

    # -- construction de la liste ------------------------------------

    def _populate_tree(self):
        confirmed_uniques = {(e["id"], e["product"], e["cve_id"]) for e in self.ordered_entries if e['kind'] == 'confirmed'}
        candidates_uniques = {(e["id"], e["product"], e.get('score'), e["cve_id"]) for e in self.ordered_entries if e['kind'] == 'candidate'}

        bold = QFont()
        bold.setBold(True)

        confirmed_root = QTreeWidgetItem([f"Alertes confirmées ({len(confirmed_uniques)})"])
        confirmed_root.setFlags(confirmed_root.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        confirmed_root.setFont(0, bold)
        self.tree.addTopLevelItem(confirmed_root)

        def confirmed_sort(entry):
            return entry[1].lower()  # product

        for entry in sorted(confirmed_uniques, key=confirmed_sort):
            label = f"{entry[2]}   {entry[1]}"  # cve_id, product
            item = QTreeWidgetItem([label])
            item.setData(0, Qt.ItemDataRole.UserRole, entry[0])
            confirmed_root.addChild(item)

        candidates_root = QTreeWidgetItem([f"Candidats à revoir ({len(candidates_uniques)})"])
        candidates_root.setFlags(candidates_root.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        candidates_root.setFont(0, bold)
        self.tree.addTopLevelItem(candidates_root)

        def candidates_sort(entry):
            return str(entry[2]) + entry[1].lower()  # score + product

        for entry in sorted(candidates_uniques, key=candidates_sort, reverse=True):
            score = entry[2]
            score_txt = f"  (score {round(score)})" if score is not None else ""
            label = f"{entry[3]}   {entry[1]}{score_txt}"
            item = QTreeWidgetItem([label])
            item.setData(0, Qt.ItemDataRole.UserRole, entry[0])
            candidates_root.addChild(item)

        self.tree.expandAll()

    # -- Update (à la demande, en tâche de fond) -----------------------

    def _update(self):
        #  Synchronise le dépôt git des CVEs, les métadonénes des paquets et met à jour la base de données

        self.update_thread = QThread(self)
        self.update_worker = UpdateWorker(self.repo_path)
        self.update_worker.moveToThread(self.update_thread)
        self.update_thread.started.connect(self.update_worker.run)
        self.update_worker.finished.connect(self._on_update_finished)
        self.update_worker.failed.connect(self._on_update_failed)
        self.update_worker.finished.connect(self.update_thread.quit)
        self.update_worker.failed.connect(self.update_thread.quit)
        self.update_thread.start()
        # self.dialogue = UpdateWindow()
        # self.dialogue.exec()

    def _on_update_failed(self):
        # self.dialogue.spinner.stop()
        # self.dialogue.close()
        pass

    def _on_update_finished(self):
        # self.dialogue.spinner.stop()
        # self.dialogue.close()
        self.tree.clear()
        self._populate_tree()

    # -- sélection ------------------------------------------------------
    def _on_selection_changed(self):
        items = self.tree.selectedItems()
        if not items:
            return
        entry_id = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not entry_id:
            return
        self._select_entry(entry_id)

    def _select_entry(self, entry_id):
        entries = [entry for entry in self.ordered_entries if entry["id"]==entry_id]
        if not entries:
            return
        self.current_entry_id = entry_id
        self._render_cve(entries[0])
        self._render_package(entries, tickets=None, loading=bool(self.bugzilla_url))
        if self.bugzilla_url:
            self._fetch_bugzilla(entries[0])

    def _manage_click(self, link):
        scheme = link.scheme()
        if scheme == 'https':
            QDesktopServices.openUrl(link)
        else:
            items = link.toString().split('/')
            if items[0] == "create":
                entry_id, pkg = items[1:]
                message = self._create_ticket(entry_id, pkg)
                if type(message) is int:
                    message = f"Ticket {message} créé"
            else:
                bug_id, cve, entry_id = items[1:]
                message = self._insert_cve(cve, bug_id)
            entries = [entry for entry in self.ordered_entries if entry["id"]==entry_id]
            if entries:
                self._render_package(entries,
                                    tickets=None,
                                    error=message,
                                    loading=bool(self.bugzilla_url)
                                    )
                if self.bugzilla_url:
                    self._fetch_bugzilla(entries[0])

    # -- rendu ------------------------------------------------------------

    def _render_cve(self, entry):
        cve = entry['cve']
        if entry['kind'] == 'confirmed':
            badge = '<span style="color:#a6291f;font-weight:600;">Alerte confirmée</span>'
        else:
            score = entry.get('score')
            score_txt = f' — score {round(score)}' if score is not None else ''
            badge = f'<span style="color:#93600c;font-weight:600;">Candidat à vérifier{esc(score_txt)}</span>'

        versions_html = ''.join(f'<li>{esc(line)}</li>' for line in cve.get('versions') or [])
        url = cve.get('url')
        url_html = f'<p><a href="{esc(url)}">{esc(url)}</a></p>' if url else ''

        html_parts = [
            f'<p>{badge}</p>',
            f'<p style="color:#5b6270;font-family:monospace;">{esc(entry["cve_id"])}</p>',
            f'<h2>{esc(cve.get("title") or entry["product"])}</h2>',
            '<p>',
        ]
        if cve.get('vendor'):
            html_parts.append(f'<b>Éditeur :</b> {esc(cve["vendor"])}<br>')
        if cve.get('product'):
            html_parts.append(f'<b>Produit :</b> {esc(cve["product"])}')
        html_parts.append('</p>')
        if cve.get('description'):
            html_parts.append(f'<p>{esc(cve["description"])}</p>')
        if versions_html:
            html_parts.append('<h3>Versions affectées</h3>')
            html_parts.append(f'<ul>{versions_html}</ul>')
        html_parts.append(url_html)

        self.cve_view.setHtml(''.join(html_parts))

    def _add_cve_link(t, cve_id):
        return ""

    def _render_package(self, entries, tickets, loading=False, error=None):
        pkgs_name = {entry.get('package').get('name') for entry in entries}
        parts = []
        if not pkgs_name:
            parts.append('<p><i>Paquet introuvable dans la base (a peut-être été retiré depuis).</i></p>')
            self.package_view.setHtml(''.join(parts))
            return
        # if len(pkgs_name) != 1:
        #     parts.append(f'<p><i>Anomalie, plusieurs paquets listés : {", ".join(pkgs_name)}.</i></p>')
        #     self.package_view.setHtml(''.join(parts))
        #     return
        for pkg_name in pkgs_name:
            versions = []
            for entry in entries:
                if entry['package']['name'] == pkg_name:
                    versions.append((entry['package']['version'], entry['distro']))
            parts.append(f'<h2 style="font-family:monospace;">{esc(pkg_name)}</h2>')
            for pkg_version, distro in versions:
                distro_txt = f" (Mageia {distro})"
                parts.append(f'<p style="color:#5b6270;">Version fournie {esc(distro_txt)} : {esc(pkg_version)}</p>')
            pkg = entry.get('package')
            if pkg is not None:
                if pkg.get('summary'):
                    parts.append(f'<p><b>{esc(pkg["summary"])}</b></p>')
                if pkg.get('description'):
                    parts.append(f'<p>{esc(pkg["description"])}</p>')
                if pkg.get('url'):
                    parts.append(f'<p><a href="{esc(pkg["url"])}">{esc(pkg["url"])}</a></p>')

        parts.append('<h3>Tickets Bugzilla</h3>')
        if loading:
            parts.append('<p><i>Recherche en cours…</i></p>')
        elif error:
            parts.append(f'<p><i>Recherche impossible : {esc(error)}</i></p>')
        elif tickets is None:
            pass
        elif not tickets:
            parts.append('<p><i>Aucun ticket trouvé.</i></p>')
        else:
            items = ''.join(
                f'<li><a href="{esc(t["url"])}">#{t["id"]}</a> {esc(t["title"])} <a href="put/{t["id"]}/{entry["cve_id"]}/{entry["id"]}">Ajouter le CVE au ticket</a></li>'
                for t in tickets
            )
            parts.append(f'<ul>{items}</ul>')
        parts.append(f'<p><a href="create/{entry["id"]}/{entry["package"]["name"]}">Créer un nouveau ticket pour le CVE {entry["cve_id"]}</a></p>')

        self.package_view.setHtml(''.join(parts))

    # -- Bugzilla (à la demande, en tâche de fond) -----------------------

    def _fetch_bugzilla(self, entry):
        package_name = entry['package']['name'] if entry.get('package') else None

        self.bugzilla_thread = QThread(self)
        self.bugzilla_worker = BugzillaWorker(self.bugzilla_url, entry['id'], entry['cve_id'], package_name)
        self.bugzilla_worker.moveToThread(self.bugzilla_thread)
        self.bugzilla_thread.started.connect(self.bugzilla_worker.run)
        self.bugzilla_worker.finished.connect(self._on_bugzilla_finished)
        self.bugzilla_worker.failed.connect(self._on_bugzilla_failed)
        self.bugzilla_worker.finished.connect(self.bugzilla_thread.quit)
        self.bugzilla_worker.failed.connect(self.bugzilla_thread.quit)
        self.bugzilla_thread.start()

    def _on_bugzilla_finished(self, entry_id, tickets):
        if entry_id != self.current_entry_id:
            return  # la sélection a changé entretemps : on jette le résultat
        entries = [entry for entry in self.ordered_entries if entry["id"]==entry_id]
        if entries:
            self._render_package(entries, tickets=tickets)

    def _on_bugzilla_failed(self, entry_id, message):
        if entry_id != self.current_entry_id:
            return
        entries = [entry for entry in self.ordered_entries if entry["id"]==entry_id]
        if entries:
            self._render_package(entries, tickets=None, error=message)

    """Ajoute une CVE au titre et au champ cf_cve d'un bug de bugs.mageia.org.

    Usage :
        export BUGZILLA_API_KEY="votre_clé"
    """
    CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    def add_to_summary(self, summary: str, cve: str) -> str:
        """Insère la CVE juste après la dernière CVE du titre, sinon à la fin."""
        if cve in (m.upper() for m in self.CVE_RE.findall(summary)):
            return summary
        matches = list(self.CVE_RE.finditer(summary))
        if matches:
            end = matches[-1].end()
            return f"{summary[:end]}, {cve}{summary[end:]}"
        return f"{summary} {cve}"

    def add_to_cf_cve(self, field: str, cve: str) -> str:
        """Ajoute la CVE au champ en reprenant le séparateur déjà utilisé."""
        field = (field or "").strip()
        if cve in (m.upper() for m in self.CVE_RE.findall(field)):
            return field
        if not field:
            return cve
        sep = ", " if "," in field else " "
        return f"{field}{sep}{cve}"

    def _insert_cve(self, cve, bug_id) -> int:
        BASE = self.bugzilla_url + "/rest"
        if not self.CVE_RE.fullmatch(cve):
            return f"Format de CVE invalide : {cve}"

        api_key = os.environ.get("BUGZILLA_API_KEY")
        if not api_key:
            return "Variable BUGZILLA_API_KEY non définie."

        s = requests.Session()
        s.headers.update({"X-BUGZILLA-API-KEY": api_key})

        # 1. Lecture
        r = s.get(
            f"{BASE}/bug/{bug_id}",
            params={"include_fields": "id,summary,cf_cve,last_change_time"},
            timeout=30,
        )
        r.raise_for_status()
        bug = r.json()["bugs"][0]

        old_summary = bug["summary"]
        old_cf = bug.get("cf_cve") or ""
        new_summary = self.add_to_summary(old_summary, cve)
        new_cf = self.add_to_cf_cve(old_cf, cve)

        payload = {}
        if new_summary != old_summary:
            payload["summary"] = new_summary
        if new_cf != old_cf.strip():
            payload["cf_cve"] = new_cf

        if not payload:
            return "Rien à modifier : la CVE est déjà présente partout."

        #  Emplacement pour vérification

        # 3. Soumission (last_change_time évite d'écraser une modif concurrente)
        payload["last_change_time"] = bug["last_change_time"]
        payload["api_key"] = api_key
        r = s.put(f"{BASE}/bug/{bug_id}", json=payload, timeout=30)
        if not r.ok:
            return f"Erreur {r.status_code} : {r.text}"
        return ""

    def _create_ticket(self, id, pkg_name):
        BASE = self.bugzilla_url + "/rest"
        current_cve = self.entries_by_id[id]
        cve = current_cve["cve_id"]
        if not self.CVE_RE.fullmatch(cve):
            return f"Format de CVE invalide : {cve}"

        api_key = os.environ.get("BUGZILLA_API_KEY")
        if not api_key:
            return "Variable BUGZILLA_API_KEY non définie."

        # get URLs
        urls = ["", "References:"] +  \
               cc.get_cve_reference_urls(cc.load_cve_by_id(self.repo_path, cve))

        dialogue = TicketSubmission(
            summary=f"{pkg_name}, security alert {cve}",
            description="<BR />\n".join([current_cve.get('cve').get('description')] + urls),
            cve=cve,
            )
        if dialogue.exec() == QDialog.DialogCode.Accepted:
            payload = dialogue.payload()
            payload["api_key"] = api_key
        else:
            return

        s = requests.Session()
        s.headers.update({"X-BUGZILLA-API-KEY": api_key})
        r = s.post(f"{BASE}/bug", json=payload, timeout=30)
        if not r.ok:
            return f"Erreur {r.status_code} : {r.text}"
        if r.text.startswith("<!DOCTYPE html>"):
            return "Protection active"
        if r.json():
            return r.json().get("id")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-path', default=None, help="Chemin du clone local de cvelistV5")
    args, qt_args = parser.parse_known_args()

    repo_path = args.repo_path or getattr(
        config, 'CVE_REPO_PATH', os.path.join(config.EXTERNAL_PATH, 'cvelistV5')
    )
    bugzilla_url = getattr(config, 'BUGZILLA_URL', None)

    app = QApplication([sys.argv[0]] + qt_args)
    window = MainWindow(bugzilla_url, repo_path)
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
