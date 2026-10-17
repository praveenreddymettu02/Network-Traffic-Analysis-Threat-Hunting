from flask import Blueprint, render_template

views_bp = Blueprint('views', __name__)


@views_bp.route('/')
def dashboard():
    return render_template('dashboard.html')


@views_bp.route('/protocols')
def protocols():
    return render_template('protocols.html')


@views_bp.route('/tcp')
def tcp_analysis():
    return render_template('tcp_analysis.html')


@views_bp.route('/visualizations')
def visualizations():
    return render_template('visualizations.html')


@views_bp.route('/dns')
def dns_monitor():
    return render_template('dns_monitor.html')


@views_bp.route('/mitre')
def mitre_dashboard():
    return render_template('mitre_dashboard.html')


@views_bp.route('/hunting')
def threat_hunting():
    return render_template('threat_hunting.html')

