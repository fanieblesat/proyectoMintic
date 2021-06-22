import sqlite3
from sqlite3 import Error
from flask import g

def get_db():# conect a la base de datos sqlite.
    try:
        if 'db' not in g:
            g.db = sqlite3.connect('almacen.db')
            return g.db
    except Error:
        print(Error)

def close_db():# cierre la cone a la base de datos.
    db = g.pop('db',None)
    if db is not None:
        db.close()