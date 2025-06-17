#!/usr/bin/env python3
"""
Database utilities for PUCP Cloud Orchestrator
"""
import sqlite3
import os
from flask import g

DATABASE = os.path.join(os.path.dirname(__file__), 'slice_service.db')

def get_db():
    """Obtiene conexión a la base de datos con manejo de errores"""
    if 'db' not in g:
        try:
            g.db = sqlite3.connect(DATABASE)
            g.db.row_factory = sqlite3.Row
        except Exception as e:
            print(f"Error connecting to database: {e}")
            raise
    return g.db

def close_db(e=None):
    """Cierra la conexión a la base de datos"""
    db = g.pop('db', None)
    if db is not None:
        db.close()