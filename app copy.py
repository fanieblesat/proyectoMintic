# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, flash, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_required, LoginManager, login_user, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import utils
import os
import yagmail
import inventory 
import sqlite3
from __init__ import db, create_app
from models import User
from datetime import datetime
from flask import Flask, render_template, request, flash, jsonify, \
    redirect, session, g, url_for, send_file, make_response, send_from_directory, abort
from db import get_db, close_db
from werkzeug.local import LocalProxy as LP
from passlib.hash import sha256_crypt
from werkzeug.utils import secure_filename
##################################################################################################################
import usuario
from flask_mail import Mail, Message 
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
import jwt
from time import time
##################################################################################################################
import imghdr


import functools

app = Flask(__name__)
#Configure the app, for image-validations purposes
#This will make the max file size 5 mb and will only allow the extensions
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif', '.jpeg']
##################################################################################################################
app.config['UPLOAD_PATH'] = 'uploads'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = "almacengrupoamisiontic2020@gmail.com"
app.config['MAIL_PASSWORD'] = "Almacen.Grupo.2020"
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
##################################################################################################################

#Validate image extension
def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    if not format:
        return None
    return '.' + (format if format != 'jpeg' else 'jpg')

app.secret_key = os.urandom(24)

#Start the connection to the database
with app.app_context():
    close_db()
    db=get_db()
    

#Start the login manager
login_manager=LoginManager() 
login_manager.init_app(app)

#Configure the login manager
@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    db.execute("SELECT * FROM user")
    return 

#Validate the user is logged in.
@app.before_request
def load_logged_user():
    user_id = session.get('user_id')
    print(user_id)
    if user_id is None:
        g.user = None
    else:
        close_db()
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id_user=?', (user_id,)
        ).fetchone()


#Redirect to login if the user is not logged in
def login_required(view):
    @functools.wraps( view )
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Inicia sesión para poder acceder al contenido de la aplicación")
            return redirect( url_for( 'login' ) )
        return view( **kwargs )

    return wrapped_view


# APP

#LOGIN

@app.route('/login', methods = ['POST', 'GET'])
def login():
    #Validate if there is an user session.
    #If there is, go to principal.
    #When the form is filled, a POST request is made to this route.
    #When there is a POST request, validates if the user is in the user table.
    #If it is, if the email and password match the records, it stats a session
    #If it isn't, it re loads the page.
    #The passwords on the dbs are hashed and salted.
    try:
        if g.user:
            flash("Ya realizaste el login, "+session['name'])
            return redirect(url_for("principal"))
        if(request.method == 'POST'):
            username = request.form.get("usuario")
            password = request.form.get("contrasena")
            close_db()
            db=get_db()
            if not username:
                error="Debe ingresar un usuario"
                flash(error)
                return render_template('index.html')
                flash(error)

            if not password:
                error = "Contraseña es requerida"
                flash(error)
                return render_template('login.html')
            print("usuario" + username + " clave:" + password)


            user = db.execute(
                'SELECT * FROM user WHERE email = ?', (username, )
            ).fetchone()
            

            if user is None:
                error = 'Usuario no registrado'
                flash(error)
            else:
                if (sha256_crypt.verify(password,user[3])):
                    session.clear()
                    session['user_id'] = user[0]
                    session['name']=user[1]
                    session['mail']=user[2]
                    session['admin']=user[4]
                    resp = make_response(redirect(url_for('principal')))
                    resp.set_cookie('username', username)
                    return resp
                else: flash("Contraseña no concuerda con los registros para el usuario")
            
            
            return render_template('index.html')

        return render_template('index.html')
    except TypeError as e:
        print("Ocurrio un eror:", e)
        return render_template('index.html')

            


@app.route('/registrar', methods = ['POST', 'GET'])
@login_required
def registrar():
    #Requires login and being admin.
    #Allows the admin to register new users.
    #When the form is send, if the mail is not on the user table, it adds the user.
    #The password is hashed and salted and saved that way.

    if session['admin']=='true':
        if(request.method=='POST'):
            close_db()
            db=get_db()
            user_mail = request.form.get("mail")
            user_name = request.form.get("name")
            pass_w=request.form.get("contrasena")
            password=sha256_crypt.using(rounds=535000).hash(str(pass_w))
            user = db.execute(
                    'SELECT * FROM user WHERE email = ?', (user_mail, )
                ).fetchone()          
            if user:
                error = 'Correo ya registrado. Por favor, prueba con otro correo'
                flash(error)
            else:
                close_db()
                db = get_db()
                db.execute(
                'INSERT INTO user ( name, email, pass, is_admin)'
                ' VALUES (?,?,?,?)',
                (user_name, user_mail, password, 'false'))
                db.commit()
                flash("Has registrado a "+user_name+" correctamente. Se le han enviado sus credenciales al usuario creado.")
##################################################################################################################
                msg = Message()
                msg.subject = "Bienvenid@ "+user_name+ " a Almacen Grupo A"
                msg.recipients = [user_mail]
                msg.sender = "almacengrupoamisiontic2020@gmail.com"
                msg.html = "<html> \
                            <head><title>Hola "+ user_name +" </title></head> \
                            <h2>Hola "+ user_name +"</h2> \
                            <body><h3>El administrador "+session['name']+" te ha registrado en la aplicación de inventario. Tus credenciales son: <br> Email: "+user_mail+" <br> Contraseña: "+ pass_w+". Accede a ella en https://3.80.19.135:2022/login</h3> \
                            <hr> \
                            <h4>Cordialmente,</h4> \
                            <h4>Almacen Grupo A</h4> \
                            </body> \
                            </html>"
                mail.send(msg)
            return redirect(url_for("principal"))
##################################################################################################################
        return render_template('registrar_usuario.html')
    else: 
        flash("No tienes permiso para ver esto.")
        return redirect(url_for("principal"))



@app.route('/recuperar')
def recuperar():
    
    return render_template('recuperar.html')



@app.route('/', methods = ['POST', 'GET'])
@login_required
def principal():

    #Main page. Requires login.
    #All of the subpages generate POST requests to this page their forms are used.
        #If it's "agregar" (adding a product), it adds the item to the database. 
        #If it's "editar" (edit a product), it updates it's values
        #If it's "delete" (delete a product), it deletes it from the database
    #Agregar and delete require admin status and will flash an error if a non-admin user tries to do them.
    #Before the queries, the app validates if the query is possible and shows an error:
        #To edit, the name or the id (at least one) must stay the same.
        #To add, the name or id must not be in the database.
        #There is no validation on delete, as the

    
    if(request.method == 'POST'):
        ###AGREGAR####
        if request.args.get("agregar"):
            print("agregar")
            id_item= request.form.get("id")
            qty = request.form.get("qty")
            name= request.form.get("name")
            mail=session['mail']
            datetimeval=datetime.now()
            uploaded_file = request.files["image_file"]
            filename= secure_filename(uploaded_file.filename)
            if session['admin']=='true':
                if filename != '':
                    file_ext = os.path.splitext(filename)[1]
                    if file_ext not in app.config['UPLOAD_EXTENSIONS'] or file_ext != validate_image(uploaded_file.stream):
                        abort(400)
                    uploaded_file.save(os.getcwd()+os.path.join('\\static\\avatars',id_item))
                close_db()
                db = get_db()
                filter_query=db.execute('SELECT * FROM product WHERE ref=? ',(id_item,)).fetchall()
                if filter_query:
                    flash("El producto ya existe. Use otro ID o nombre")
                    return render_template("agregar.html")
                else:
                    close_db()
                    db = get_db()
                    db.execute(
                    'INSERT INTO product (ref, nom, cant, email_last_modified, date_last_modified )'
                    ' VALUES (?, ?, ?,?,?)',
                    (id_item,  name, qty, mail, datetimeval))
                    db.commit()
                    flash("Producto agregado. Referencia: "+id_item+", Nombre: "+name+", Inventario Inicial: "+qty )
            else: flash("No tienes permiso para realizar esta acción")
        ### EDITAR ###
        if request.args.get("editar"):
            print("editar")
            id_item= request.form.get("id")
            qty = request.form.get("qty")
            name= request.form.get("name")
            mail=session['mail']
            datetimeval=datetime.now()
            if session['admin']=='true':
                uploaded_file = request.files["image_file"]
                filename= secure_filename(uploaded_file.filename)
                if filename != '':
                    file_ext = os.path.splitext(filename)[1]
                    if file_ext not in app.config['UPLOAD_EXTENSIONS'] or file_ext != validate_image(uploaded_file.stream):
                        abort(400)
                    uploaded_file.save(os.getcwd()+os.path.join('\\static\\avatars',id_item))
            close_db()
            db = get_db()
            filter_query=db.execute('SELECT * FROM product WHERE ref=? or nom=?', (id_item, name)).fetchall()
            if not filter_query:
                flash("Fallo en edición. No cambie a la vez nombre e ID. Intente nuevamente.")
                
 
            else:
                close_db()
                db = get_db()
                print((id_item,  name, qty, mail, datetimeval,id_item, name))
                db.execute(
                'UPDATE product \
                SET ref = ?, nom=?, cant=?, email_last_modified=?, date_last_modified=?\
                WHERE ref=? OR nom=?',
                (id_item,  name, qty, mail, datetimeval,id_item, name))
                db.commit()
                flash("Producto editado. Referencia: "+id_item+", Nombre: "+name+", Inventario: "+qty)

        ### ELIMINAR ###
        if request.args.get("delete"):
            print("Eliminar")
            id_item= request.args.get("id")
            name = request.args.get("name")
            stock=request.args.get("stock")
            print(id_item)
            if session['admin']=='true':
                close_db()
                db = get_db()
                if db.execute("SELECT * FROM product where ref=?",(id_item,)).fetchone():
                    close_db()
                    db = get_db()
                    db.execute('DELETE FROM product WHERE ref=?',(id_item,))
                    db.commit()
                    flash("Producto eliminado. Sus datos eran ID: "+id_item+", Nombre: "+name+", Inventario: "+stock)
                else: flash("No hay producto con el ID suministrado")
            else : flash("No tienes permiso para realizar esta acción")
    


    close_db()
    with sqlite3.connect("almacen.db") as dbP:
        cursorProd = dbP.cursor()
    if not request.form.get("term"):
        find_prod = ("SELECT * FROM product ORDER BY nom ASC")
        cursorProd.execute(find_prod)
        resultsProd = cursorProd.fetchall()
    else:
        find_prod = ("SELECT * FROM product WHERE (instr(lower(ref),  lower(?))>0) OR (instr(lower(nom),  lower(?))>0)\
        ORDER BY nom ASC")
        cursorProd.execute(find_prod, (request.form.get("term"),request.form.get("term")))
        resultsProd = cursorProd.fetchall()
        
  
    inventory1=[inventory.Inventory(i[0], i[1], i[2], i[3], i[4]) for i in resultsProd]
    return render_template('principal.html', inventory=inventory1, user_name =session['name'], admin=session['admin'])
      
@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))
##################################################################################################################
@app.route('/recuperar_contrasena', methods = ['POST', 'GET'])
def recuperar_contrasena():
    if(request.method == 'POST'):
        email_psw = request.form.get("emailpsw")
        with sqlite3.connect("almacen.db") as dbC:
            cursorPass = dbC.cursor()
        find_pass = ('SELECT * FROM user WHERE email = ?')
        cursorPass.execute(find_pass, [(email_psw)])
        resultsContra = cursorPass.fetchall()
        rec_usuario = [usuario.Usuario(i[0], i[1], i[2], i[3], i[4]) for i in resultsContra]

        token = jwt.encode({'reset_password': rec_usuario[0].email, 'exp': time() + 60*60*24},
                           key=app.secret_key)

        msg = Message()
        msg.subject = "Almacen Grupo A - Restablecer contraseña"
        msg.sender = "almacengrupoamisiontic2020@gmail.com"
        msg.recipients = [rec_usuario[0].email]
        msg.html = render_template('reset_email.html', user=rec_usuario[0].email, token=token)

        mail.send(msg)
    return redirect(url_for('login'))
##################################################################################################################

@app.route('/agregar')
@login_required
def agregar():
    if session['admin']=='false':
        return redirect(url_for('principal'))


    return render_template('agregar.html')

@app.route('/editar', methods = ['POST', 'GET'])
@login_required
def editar():
    if(request.method == 'POST'):
        item_id= request.args.get("id")
        item_name = request.args.get("name")
        item_stock=request.args.get("stock")

    return render_template('editar.html', admin=session['admin'], item_id=item_id, item_name=item_name, item_stock=item_stock)
##################################################################################################################
@app.route('/password_reset_verified/<token>', methods=['GET', 'POST'])
def reset_verified(token):

    username = jwt.decode(token, key=app.secret_key)['reset_password']
    print(username)

    with sqlite3.connect("almacen.db") as con:
        cur = con.cursor()
    user = cur.execute('SELECT * FROM user WHERE email = ?', (username, )).fetchone() 
    con.commit()
    con.close()


    if not user:
        print('no user found')
        return redirect(url_for('login'))

    password = request.form.get('password')
    if password:
        with sqlite3.connect("almacen.db") as cond:
            curs = cond.cursor()
        contra = sha256_crypt.using(rounds=535000).hash(str(password))
        curs.execute(
        'UPDATE user \
        SET pass=?\
        WHERE email=?',
        (contra,  username))
        
        cond.commit()
        cond.close()
        msg = Message()
        msg.subject = "Contraseña reestablecida correctamente"
        msg.recipients = [username]
        msg.sender = "almacengrupoamisiontic2020@gmail.com"
        msg.html = "<html> \
                    <head><title>Contraseña reestablecida</title></head> \
                    <h2>Hola recibe un cordial saludo</h2> \
                    <body><h3>Tu contraseña se ha restablecido correctamente, recuerda que tus credenciales son: <br> Email: "+username+" <br> Contraseña: "+ password+"</h3> \
                    <hr> \
                    <h4>Cordialmente,</h4> \
                    <h4>Almacen Grupo A</h4> \
                    </body> \
                    </html>"
        mail.send(msg)    

        return redirect(url_for('login'))

    return render_template('reset_verified.html')
##################################################################################################################
if __name__ == '__main__':
    app.run(debug=True)


