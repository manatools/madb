import os
import tempfile

import pytest
from flask import Flask
from flask import request
import pytest
from madb.app import create_app

@pytest.fixture
def app():

    app = create_app()

    yield app

@pytest.fixture()
def client(app):
    return app.test_client()


def test_homepage(client):
    """Check that home page is accessible."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Welcome to Mageia App DB" in resp.data

def test_qaupdates(client):
    """Check that QA updates page is accessible."""
    resp = client.get("/updates/")
    assert resp.status_code == 200
    assert b"Current Update candidates" in resp.data

def test_blockers(client):
    """Check that blockers page is accessible."""
    resp = client.get("/blockers/")
    assert resp.status_code == 200
    assert b"Current Blockers" in resp.data

def test_highpriority(client):
    """Check that highpriority page is accessible."""
    resp = client.get("/highpriority/")
    assert resp.status_code == 200
    assert b"High Priority Bugs for next release" in resp.data

def test_milestone(client):
    """Check that milestone page is accessible."""
    resp = client.get("/milestone/")
    assert resp.status_code == 200
    assert b"Intended for next release" in resp.data

#def test_submission(client):
#    """Vérifier que la soumission du formulaire fonctionne."""
#    resp = client.post("/package", data={"package_name": "numpy", "architecture": "x86"}, follow_redirects=True)
#    assert b"Informations complémentaires sur numpy" in resp.data

#def test_invalid_submission(client):
#    """Vérifier qu'une tentative de validation non valide renvoie une erreur."""
#    resp = client.post("/show", data={}, follow_redirects=True)
#    assert b"Error" in resp.data