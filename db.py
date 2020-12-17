import sqlite3
from sqlite3 import Error
from flask import g


def get_db(): #method for connecting to the database
    try:
        if 'db' not in g:
            g.db = sqlite3.connect('proyecto.db')
            return g.db
    except Error:
        print(Error)


def close_db(): #closing connection
    db = g.pop('db', None)
    if db is not None:
        db.close()