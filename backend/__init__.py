from flask import Flask, cli, render_template
from flasgger import Swagger
from recon.core import base
from recon.core.constants import BANNER_WEB
from backend.db import Tasks
import os

try:
    from redis import Redis
    import rq
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    Redis = None
    rq = None

# disable the development server warning banner
cli.show_server_banner = lambda *x: None

print(BANNER_WEB)

# create an application-wide framework and tasks instance
recon = base.Recon(check=False, analytics=False, marketplace=True)
recon.start(base.Mode.WEB)
tasks = Tasks(recon)

# configuration
DEBUG = False
SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24).hex()
JSON_SORT_KEYS = False
REDIS_URL = os.environ.get('REDIS_URL', 'redis://')
SWAGGER = {
    'title': 'Swagger',
    'info': {
        'title': 'Recon-API',
        'description': 'A RESTful API for Recon-ng',
        'version': '0.0.1',
    },
    'uiversion': 3,
    'specs_route': '/api/',
}
WORKSPACE = os.path.basename(recon.workspace)
print((f" * Workspace initialized: {WORKSPACE}"))

def create_app():

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(root_dir, 'frontend', 'templates')
    static_dir = os.path.join(root_dir, 'frontend', 'static')

    # Setting static_url_path to blank serves static files from the web root
    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
        static_url_path=''
    )
    app.config.from_object(__name__)

    definitions_path = os.path.join(os.path.dirname(__file__), 'definitions.yaml')
    Swagger(app, template_file=definitions_path)

    if HAS_REDIS and app.config.get('REDIS_URL'):
        try:
            app.redis = Redis.from_url(app.config['REDIS_URL'])
            app.task_queue = rq.Queue('recon-tasks', connection=app.redis)
        except Exception:
            app.redis = None
            app.task_queue = None
    else:
        app.redis = None
        app.task_queue = None

    @app.after_request
    def disable_cache(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return response

    @app.route('/')
    def index():
        return render_template('index.html', workspaces=recon._get_workspaces())

    from backend.api import resources
    app.register_blueprint(resources)

    return app
