from app import *

paranoid = Paranoid(app)
paranoid.redirect_view = '/'


@app.route('/')
def index():
    return render_template('index.html')


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=60)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@paranoid.on_invalid_session
def invalid_session():
    render_template('404.html'), 401
