from flask import Flask, render_template, request

app = Flask(__name__)


@app.route('/')
def home():
    """Home page - simple landing page."""
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page.
    - GET: shows the login form.
    - POST: accepts username/password, does NOT perform real authentication,
      and displays a fake welcome message using the submitted username.
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        # Password is intentionally ignored for this demo.
        # password = request.form.get('password', '')
        return render_template('login.html', username=username, submitted=True)

    return render_template('login.html', submitted=False)


@app.route('/search')
def search():
    """
    Search page.
    - Reads the 'q' query parameter and echoes it back on the page.
    """
    query = request.args.get('q', '')
    return render_template('search.html', query=query)


@app.route('/profile/<username>')
def profile(username):
    """Dummy profile page for any given username."""
    return render_template('profile.html', username=username)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """
    Contact page.
    - GET: shows the contact form.
    - POST: processes the submitted name, email, and message,
      then displays a thank-you message with the submitted data.
    """
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        message = request.form.get('message', '')
        return render_template(
            'contact.html',
            submitted=True,
            name=name,
            email=email,
            message=message
        )

    return render_template('contact.html', submitted=False)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)