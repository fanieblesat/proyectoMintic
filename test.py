from db import get_db, close_db
app.app_context(app=db)
close_db()
db=get_db()
db.execute('SELECT * FROM user')
