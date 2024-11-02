from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'
mysql = MySQL(app)

# Configuración de la base de datos
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mendoza2004'
app.config['MYSQL_DB'] = 'doctora_db'

mysql = MySQL(app)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nombre_usuario = request.form['nombre_usuario']
        contrasena = request.form['contrasena']

        cur = mysql.connection.cursor()
        cur.execute("SELECT pass_usuario FROM Usuarios WHERE nom_usuario = %s", (nombre_usuario,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[0], contrasena):
            session['nombre_usuario'] = nombre_usuario
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        nombre_usuario = request.form['nombre_usuario']
        correo_usuario = request.form['correo_usuario']
        telefono_usuario = request.form['telefono_usuario']
        contrasena = request.form['contrasena']
        confirmar_contrasena = request.form['confirmar_contrasena']

        if contrasena != confirmar_contrasena:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(contrasena)

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM Usuarios WHERE nom_usuario = %s OR correo_usuario = %s",
                       (nombre_usuario, correo_usuario))
        user = cursor.fetchone()

        if user:
            flash('El nombre de usuario o correo ya están registrados', 'error')
        else:
            cursor.execute("INSERT INTO Usuarios (nom_usuario, correo_usuario, pass_usuario, telefono_usuario, direccion_usuario) VALUES (%s, %s, %s, %s, %s)",
                           (nombre_usuario, correo_usuario, hashed_password, telefono_usuario, nombre))
            mysql.connection.commit()
            flash('Registro exitoso, ahora puedes iniciar sesión', 'success')
            return redirect(url_for('login'))

        cursor.close()
    
    return render_template('register.html')

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        nombre_usuario = request.form['nombre_usuario']
        correo = request.form['correo']
        nueva_contrasena = request.form['nueva_contrasena']
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM Usuarios WHERE nom_usuario = %s AND correo_usuario = %s", (nombre_usuario, correo))
        user = cursor.fetchone()

        if user:
            nueva_contrasena_hashed = generate_password_hash(nueva_contrasena)
            cursor.execute("UPDATE Usuarios SET pass_usuario = %s WHERE id_usuario = %s", (nueva_contrasena_hashed, user[0]))
            mysql.connection.commit()
            cursor.close()
            
            flash('Contraseña actualizada exitosamente.', 'success')
            return redirect(url_for('login'))
        else:
            cursor.close()
            flash('Usuario o correo electrónico incorrecto.', 'danger')
            return redirect(url_for('recuperar_contrasena'))
    return render_template('recuperar_contrasena.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/testimonios')
def testimonios():
    return render_template('testimonios.html')

@app.route('/atencion')
def atencion():
    return render_template('atencion.html')

@app.route('/contacto')
def contacto():
    return render_template('contacto.html')

@app.route('/dashboard')
def dashboard():
    if 'nombre_usuario' not in session:
        flash('Debes iniciar sesión primero.', 'danger')
        return redirect(url_for('login'))
    current_year = datetime.now().year
    return render_template('dashboard.html', title="Dashboard", current_year=current_year)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('nombre_usuario', None)
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
