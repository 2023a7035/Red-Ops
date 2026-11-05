"""
RedOps – Automated Enterprise Red Team Assessment and Attack Simulation Platform
Main Application Factory & Server Entrypoint
"""
import os
import sys
from flask import Flask, render_template

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import Config
from database.db import init_db
from database.seed_data import seed_database

# Import Blueprints
from routes.dashboard_routes import dashboard_bp
from routes.discovery_routes import discovery_bp
from routes.vulnerability_routes import vulnerability_bp
from routes.graph_routes import graph_bp
from routes.ai_routes import ai_bp
from routes.simulation_routes import simulation_bp
from routes.planner_routes import planner_bp
from routes.reporting_routes import reporting_bp
from routes.settings_routes import settings_bp

def create_app():
    """Application factory initializing database, registering routes, and configuring security."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize Database Schema & Seed Data if fresh
    init_db()
    seed_database(force_refresh=False)

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(discovery_bp)
    app.register_blueprint(vulnerability_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(simulation_bp)
    app.register_blueprint(planner_bp)
    app.register_blueprint(reporting_bp)
    app.register_blueprint(settings_bp)

    @app.context_processor
    def inject_global_metadata():
        return {
            "app_title": "RedOps",
            "app_subtitle": "Automated Enterprise Red Team Assessment and Attack Simulation Platform",
            "app_version": "v2.4.0-Enterprise",
            "year": 2026,
            "ai_provider": Config.AI_PROVIDER
        }

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template("500.html", error=str(e)), 500

    return app

if __name__ == "__main__":
    app = create_app()
    print("=" * 72)
    print(" [!] REDOPS ENTERPRISE PLATFORM INITIALIZED")
    print(f" [*] Authorized Scope: {Config.AUTHORIZED_TARGETS_RAW}")
    print(f" [*] AI Reasoning Engine: {Config.AI_PROVIDER.upper()}")
    print(f" [*] Server running at: http://{Config.HOST}:{Config.PORT}")
    print("=" * 72)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
