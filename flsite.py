from flask import Flask, render_template, url_for, request, flash, session, redirect, abort, g, make_response
import sqlite3
import os
from FDataBase import FDataBase
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from UserLogin import UserLogin

DATABASE = '/tmp/flsite.db'
DEBUG = True
SECRET_KEY = 'vkdgv653kdugudg7w34874'
MAX_CONTENT_LENGTH = 1024 * 1024

app = Flask(__name__)
app.config['SECREY_KEY'] = 'gnd54bkjgyi27r97mrbflicozczhcbf74nhih8g8g88888gojg'
app.config.from_object(__name__)

app.config.update(dict(DATABASE=os.path.join(app.root_path, 'flsite.db')))

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Авторизируйтесь для того чтобы иметь доступ к закрытым страницам.'
login_manager.login_message_category = 'success'


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    dbase = FDataBase(db)
    return UserLogin().fromDB(user_id, dbase)


def connect_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


def create_db():
    db = connect_db()
    with app.open_resource('sq_db.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()


def get_db():
    if not hasattr(g, 'link_db'):
        g.link_db = connect_db()
    return g.link_db


@app.route("/")
def index():
    db = get_db()
    dbase = FDataBase(db)
    return render_template('index.html', menu=dbase.getMenu())


@app.route("/readreviews")
def readreviews():
    db = get_db()
    dbase = FDataBase(db)
    return render_template('readreviews.html', menu=dbase.getMenu(), posts=dbase.getPostsAnonce())


@app.route("/reviews", methods=["POST", "GET"])
@login_required
def reviews():
    db = get_db()
    dbase = FDataBase(db)
    if request.method == "POST":
        if len(request.form['name']) > 3 and len(request.form['post']) > 10 and request.form['name'][0].upper() == \
                request.form['name'][0]:
            res = dbase.addPost(request.form['name'], request.form['post'], request.form['url'])
            if not res:
                flash('Ошибка добавления отзыва', category='error')
            else:
                flash('Отзыв добавлен успешно', category='success')
        else:
            if request.form['name'][0].upper() != request.form['name'][0]:
                flash('Название отзыва написано не с заглавной буквы', category='error')
            if len(request.form['name']) <= 3:
                flash('Недостаточное количество символов в название отзыва', category='error')
            if len(request.form['post']) <= 10:
                flash('Недостаточное количество символов в тексте отзыва', category='error')

    return render_template('reviews.html', menu=dbase.getMenu())


@app.route("/post/<alias>")
def showPost(alias):
    db = get_db()
    dbase = FDataBase(db)
    title, post = dbase.getPost(alias)
    if not title:
        abort(404)

    return render_template('post.html', menu=dbase.getMenu(), post=post)


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/mexico')
def mexico():
    return render_template("mexico.html")


@app.route('/cuba')
def cuba():
    return render_template("cuba.html")


@app.route('/domicana')
def domicana():
    return render_template("domicana.html")


@app.route('/costarica')
def costarica():
    return render_template("costarica.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    db = get_db()
    dbase = FDataBase(db)
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == "POST":
        user = dbase.getUserByEmail(request.form['email'])
        if user and check_password_hash(user['psw'], request.form['psw']):
            userlogin = UserLogin().create(user)
            rm = True if request.form.get('remainme') else False
            login_user(userlogin, remember=rm)
            return redirect(request.args.get("next") or url_for("profile"))

        flash("Неверная пара логин или пароль", "error")

    return render_template("login.html", menu=dbase.getMenu())


@app.route('/profile')
@login_required
def profile():
    db = get_db()
    dbase = FDataBase(db)
    return render_template("profile.html", menu=dbase.getMenu())


@app.route('/userava')
@login_required
def userava():
    img = current_user.getAvatar(app)
    if not img:
        return ""

    h = make_response(img)
    h.headers['Content-Type'] = 'image/png'
    return h


@app.route('/upload', methods=["POST", "GET"])
@login_required
def upload():
    db = get_db()
    dbase = FDataBase(db)
    if request.method == 'POST':
        file = request.files['file']
        if file and current_user.verifyExt(file.filename):
            try:
                img = file.read()
                res = dbase.updateUserAvatar(img, current_user.get_id())
                if not res:
                    flash("Не удалось обновить аватар", category='error')
                    return redirect(url_for('profile'))
                flash("Аватар обновлен", category='success')
            except FileNotFoundError as e:
                flash("Ошибка чтения файла", category='error')
        else:
            flash("Не удалось обновить аватар", category='error')

    return redirect(url_for('profile'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Вы успешно вышли из аккаунта", "success")
    return redirect(url_for('login'))


@app.route('/profile/<username>')
def userprofile(username):
    if 'userLogged' not in session or session['userLogged'] != username:
        abort(401)
    return f"Профиль пользователя: {username}"


@app.route('/feedback', methods=['POST', "GET"])
def feedback():
    if request.method == 'POST':
        print(request.form['username'], ['email'], ['feedbackmessage'])
        if len(request.form['username']) > 2 and '@' in request.form['email'] and len(request.form['email']) > 3 and \
                request.form['username'][0].upper() == request.form['username'][0]:
            flash('Сообщение отправлено', category='success')
        else:
            if len(request.form['username']) <= 2:
                flash('Недостаточное количество символов в имени', category='error')
            if '@' not in request.form['email']:
                flash('Неверно введен Email', category='error')
            elif len(request.form['email']) <= 3:
                flash('Недостаточное количество символов в Email', category='error')

    return render_template("feedback.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    db = get_db()
    dbase = FDataBase(db)
    if request.method == "POST":
        session.pop('_flashes', None)
        if len(request.form['name']) > 3 and len(request.form['email']) > 4 \
                and len(request.form['psw']) > 4 and request.form['psw'] == request.form['psw2']:
            hash = generate_password_hash(request.form['psw'])
            res = dbase.addUser(request.form['name'], request.form['email'], hash)
            if res:
                flash("Вы успешно зарегистрированы", category='success')
                return redirect(url_for('login'))
            else:
                flash("Ошибка при добавлении в БД", category='error')
        else:
            if len(request.form['name']) <= 3:
                flash("Недостаточное количество символов в имени", "error")
            if '@' not in request.form['email']:
                flash('Неверно введен Email', category='error')
            elif len(request.form['email']) <= 3:
                flash('Недостаточное количество символов в Email', category='error')
            if len(request.form['psw']) <= 4:
                flash('Ваш пароль слишком простой', category='error')
                flash("Измените его чтобы зарегестрироваться", category='error')
            if request.form['psw'] != request.form['psw2']:
                flash('Пароли не совпадают', category='error')

    return render_template("register.html", menu=dbase.getMenu())


@app.errorhandler(404)
def pageNotFound(error):
    return render_template("page404.html"), 404


if __name__ == '__main__':
    app.run(debug=True)
