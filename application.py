import os
import time
import ast

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']
    current_position = ast.literal_eval(db.execute("SELECT positions FROM position WHERE user_id = ?", session['user_id'])[0]['positions'])
    stock_list = []
    stock_info = {}
    stock_total = 0

    # Look up the current price
    for symbol in current_position.keys():
        result = lookup(symbol)
        stock_info["symbol"] = symbol
        stock_info["name"] = result["name"]
        stock_info['shares'] = current_position[symbol]
        stock_info['price'] = usd(result['price'])
        stock_info['total_price'] = usd(current_position[symbol] * result['price'])
        stock_total += current_position[symbol] * result['price']
        stock_list.append(stock_info)

    assets = cash + stock_total

    # Now cash, stock_total and assets form a table while
    # stock_list forms a table

    return render_template("index.html", cash=usd(cash), stock=usd(stock_total), assets=usd(assets), positions=stock_list)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        stock = request.form.get("symbol")
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid shares")
        result = lookup(stock)

        # Validate the input
        if result == None:
            return apology("Stock not found")
        if shares <= 0:
            return apology(("Shares must be positive"))

        # Check the validity of the purchase
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        total_price = shares * result['price']
        if total_price > balance[0]['cash']:
            return apology("Balance not enough")

        # Transaction legal, submit it
        db.execute("INSERT INTO transactions (time, user_id, symbol, price, shares, total_price, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            session["user_id"],
            result['symbol'],
            result['price'],
            shares,
            total_price,
            'Buy'
        )

        # Subtract the money
        db.execute("UPDATE users SET cash= ? WHERE id = ?", balance[0]['cash'] - total_price, session['user_id'])

        # Update the position
        current_position = ast.literal_eval(db.execute("SELECT positions FROM position WHERE user_id = ?", session['user_id'])[0]['positions'])

        if current_position == None or result['symbol'] not in current_position:
            # Current user do not possess any share of the stock
            db.execute("UPDATE position SET positions=\
                    JSON_INSERT((SELECT positions FROM position WHERE user_id = ?), ?, ?)\
                    WHERE user_id = ?;",
                session['user_id'],
                '$.' + result['symbol'],
                shares,
                session['user_id']
            )
        else:
            # Current user do possess some shares of the stock
            db.execute("UPDATE position SET positions=\
                        JSON_REPLACE((SELECT positions FROM position WHERE user_id = ?), ?, ?)\
                        WHERE user_id = ?;",
                session['user_id'],
                '$.' + result['symbol'],
                shares + current_position[result['symbol']],
                session['user_id']
            )


        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get the transaction history
    history = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    for transaction in history:
        if transaction['price'] != '':
            transaction['price'] = usd(transaction['price'])
        transaction['total_price'] = usd(transaction['total_price'])

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/change_password", methods=['GET', 'POST'])
@login_required
def change_password():
    """Change the password of the account"""
     # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure older password was submitted
        if not request.form.get("older_password"):
            return apology("must provide older password", 403)

        # Ensure password was submitted
        elif not request.form.get("newer_password"):
            return apology("must provide newer password", 403)

        # Ensure password was repeated
        elif not request.form.get("repeat_password"):
            return apology("must repeat newer password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("older_password")):
            return apology("wrong password", 403)

        # Ensure newer password is correct
        elif not request.form.get("newer_password") == request.form.get("repeat_password"):
            return apology("newer password must match", 403)

        # Change the password
        password_hash = generate_password_hash(request.form.get("newer_password"))
        db.execute("UPDATE users SET hash = ? WHERE id = ?;", password_hash, session['user_id'])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_password.html")


@app.route("/add_credit", methods=["GET", "POST"])
@login_required
def add_credit():
    """Add some credit to the account."""
    if request.method == "POST":
        # Add to cash
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        db.execute("UPDATE users SET cash= ? WHERE id = ?",
                balance[0]['cash'] + float(request.form.get("credit")),
                session['user_id']
            )
        # Submit the transaction
        db.execute("INSERT INTO transactions (time, user_id, symbol, price, shares, total_price, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            session["user_id"],
            '',
            '',
            '',
            float(request.form.get("credit")),
            'Add Credit'
            )


        return redirect("/")

    return render_template("add_credit.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        result = lookup(request.form.get("symbol"))
        if result == None:
            return apology("Stock not found")

        result['price'] = usd(result['price'])
        return render_template("quoted.html", result=result)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Register the user
    if request.method == "POST":
        # Check the availability
        username = request.form.get("username")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology('Username cannot be blank!')
        if len(rows) == 1 and username == rows[0]['username']:
            return apology('Username already exists!')
        if not password :
            return apology('Password cannot be blank')
        if not confirmation :
            return apology('Confirmation cannot be blank')
        if not password == confirmation:
            return apology('Password does not match confirmation')

        # Store the registrant's data
        password_hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)
        user_id = db.execute("SELECT id FROM users WHERE username = ?", username)[0]['id']
        db.execute("INSERT INTO position (user_id, positions) VALUES (?, json('{}'))", user_id)

        return redirect("/login")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Sell some stocks
    if request.method == "POST":
        stock = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        result = lookup(stock)
        max_shares = ast.literal_eval(
                            db.execute("SELECT positions FROM position WHERE user_id = ?",
                                session['user_id']
                            )[0]['positions'])[stock]

        # Validate the input
        if result == None:
            return apology("Stock not found")
        if shares <= 0:
            return apology(("Shares must be positive"))
        if shares > max_shares:
            return apology(("Shares exceed"))

        # Transaction legal
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        total_price = shares * result['price']

        # Transaction legal, submit it
        db.execute("INSERT INTO transactions (time, user_id, symbol, price, shares, total_price, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            session["user_id"],
            result['symbol'],
            result['price'],
            shares,
            total_price,
            'Sell'
        )

        db.execute("UPDATE users SET cash= ? WHERE id = ?", balance[0]['cash'] + total_price, session['user_id'])

        if shares == max_shares:
            db.execute("UPDATE position SET positions=\
                    JSON_REMOVE((SELECT positions FROM position WHERE user_id = ?), ?)\
                    WHERE user_id = ?;",
                session['user_id'],
                '$.' + result['symbol'],
                session['user_id']
            )
        else:
            db.execute("UPDATE position SET positions=\
                    JSON_REPLACE((SELECT positions FROM position WHERE user_id = ?), ?, ?)\
                    WHERE user_id = ?;",
                session['user_id'],
                '$.' + result['symbol'],
                max_shares - shares,
                session['user_id'],
            )

        return redirect("/")

    # Select some stocks to sell
    current_position = db.execute("SELECT positions FROM position WHERE user_id = ?", session['user_id'])[0]
    return render_template("sell.html", stocks=ast.literal_eval(current_position['positions']).keys())


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
