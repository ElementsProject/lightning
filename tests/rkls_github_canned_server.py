import flask
import json
import os


def create_app(test_config=None):
    app = flask.Flask(__name__)

    @app.route("/api/repos/<github_user>/<github_repo>/contents/")
    def github_plugins_repo_api(github_user, github_repo):
        '''This emulates api.github.com calls to lightningd/plugins'''
        user = flask.escape(github_user)
        repo = flask.escape(github_repo)
        canned_api = os.environ.get('REDIR_GITHUB') + f'/rkls_api_{user}_{repo}.json'
        with open(canned_api, 'rb') as f:
            canned_data = f.read(-1)
        print(f'serving canned api data from {canned_api}')
        resp = flask.Response(response=canned_data,
                              headers={'Content-Type': 'application/json; charset=utf-8'})
        return resp

    @app.route("/api/repos/<github_user>/<github_repo>/git/trees/<plugin_name>")
    def github_plugin_tree_api(github_user, github_repo, plugin_name):
        dir_json = \
            {
                "url": f"https://api.github.com/repos/{github_user}/{github_repo}/git/trees/{plugin_name}",
                "tree": []
            }
        # FIXME: Pull contents from directory
        for file in os.listdir(f'tests/data/recklessrepo/{github_user}/{plugin_name}'):
            dir_json["tree"].append({"path": file})
        resp = flask.Response(response=json.dumps(dir_json),
                              headers={'Content-Type': 'application/json; charset=utf-8'})
        return resp

    return app


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        app.run(debug=True)
