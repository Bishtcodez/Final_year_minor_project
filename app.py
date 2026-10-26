from flask import Flask, render_template, request, redirect, url_for, jsonify  # type: ignore
from flask_cors import CORS  # type: ignore
from detector.rule_factory import RuleFactory
from detector.analyzer import analyze_email
from detector import feeds, ml

app = Flask(__name__)
CORS(app)


def check_email(email):
    """Same shape as before: {rule_name: True/False}."""
    return {name: RuleFactory.get_rule(name).check(email) for name in RuleFactory.all_rule_names()}


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'clear' in request.form:
            return redirect(url_for('index'))
        email = {
            'from': request.form['from'],
            'subject': request.form['subject'],
            'body': request.form['body'],
        }
        # `results` keeps the old bool dict so templates/index.html still works;
        # `analysis` has the verdict, score and reasons (show them in the template).
        return render_template('index.html', email=email,
                               results=check_email(email), analysis=analyze_email(email))
    return render_template('index.html', email=None, results=None, analysis=None)


def _email_from_json():
    data = request.get_json(silent=True) or {}
    return {'from': data.get('from') or '', 'subject': data.get('subject') or '',
            'body': data.get('body') or '', 'reply_to': data.get('reply_to')}


@app.route('/detect', methods=['POST'])
def detect_phishing():
    return jsonify(check_email(_email_from_json()))   # unchanged for the Chrome extension


@app.route('/analyze', methods=['POST'])
def analyze():
    return jsonify(analyze_email(_email_from_json()))  # verdict + score + reasons


@app.route('/status')
def status():
    m = ml.load_model()
    return jsonify({"feeds": feeds.get_db().status(),
                    "model": m.get("metrics") if m else None, "model_trained": m.get("trained") if m else None})


if __name__ == '__main__':
    app.run(debug=True)
