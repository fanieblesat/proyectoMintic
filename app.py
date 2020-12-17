from flask import Flask, render_template, flash, request, redirect

import validate

app = Flask(__name__)

from db import get_db, close_db


@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/register', methods=('GET', 'POST'))
def register():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            error = None
            print('Entró aquí')
            db = get_db()

        if not validate.isUsernameValid(username):
            print('El usuario no es correcto')
            error = "El usuario debe ser alfanumérico"
            flash(error)
            return render_template('register.html')

        if not validate.isEmailValid(email):
            error = "Correo inválido"
            flash(error)
            return render_template('register.html')

        if not validate.isPasswordValid(password):
            error = "La contraseña debe tener por lo menos una mayúscula y una minúscula y 8 caracteres"
            flash(error)
            return render_template('register.html')

        if db.execute('SELECT id FROM usuarios WHERE correo=?', email).fetchone() is not None:
           error = 'El correo ya existe'.format(email)
           flash(error)
           return render_template('register.html')

        db.execute('INSERT INTO usuarios (suario,correo,contraseña) VALUES (?,?,?)',(username,email,password))
        db.commit()
        flash('Usuario creado correctamente')
        return render_template('search.html')

    # return render_template('register.html')
    except Exception as e:
        print("Ocurrió un error:", e)
        return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    try:
        if request.method == 'POST':
            db = get_db()
            username = request.form['username']
            password = request.form['password']
            print(username)
            if username == " ":
                error = "Debes ingresar el usuario"
                flash(error)
                return render_template('login.html')
            if not password:
                error = "La contraseña es requerida"
                flash(error)
                return render_template('login.html')

            user = db.execute('SELECT * FROM Usuarios WHERE Usuario=? AND Contraseña=?', (username, password)).fetchone()

            if user is None:
                error = 'Usuario o contraseña inválidos'
                flash(error)
            else:
                error = 'Usuario creado correctamente'
                flash(error)
                return render_template('search.html')
        return render_template('login.html')
    except Exception as e:
        return render_template('login.html')


@app.route('/change')
def change_password():
    return render_template('change.html')


@app.route('/admin')
def option_admin():
    return render_template('admin.html')


@app.route('/nuevo')
def nuevo():
    return render_template('register.html')


@app.route('/search')
def search():
    return render_template('search.html')


if __name__ == '__main__':
    app.run()
