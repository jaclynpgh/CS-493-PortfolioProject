# Jaclyn Sabo
# CS493 Portfolio Project



import json
from urllib.parse import quote_plus

from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from google.cloud import datastore
from jose import jwt
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import urlopen
import constants
import requests

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()

# Update the values of the following 3 variables
CLIENT_ID = 'xVCMGQFd3HsP49Z93K8jJloCBSam5qaE'
CLIENT_SECRET = 'AgkuOgNM-Bsf2FQ1F5evOA4LD8V35Bn-out7HyZ6jP8mcTZreuyXRtSNgcmg4zCh'
DOMAIN = '493-sabo.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


@app.route("/")
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# --------------------------  AUTH0 USER LOGIN ----------------------------------------

# Adapted from https://auth0.com/docs/quickstart/webapp/python

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    user = auth0.get('userinfo').json()
    # add user to google datastore
    query = client.query(kind=constants.users)
    query.add_filter("id", "=", user["sub"])
    user_list = (list(query.fetch()))
    existing_user = False
    for i in user_list:
        if i['id'] == user['sub']:
            existing_user = True
    if not existing_user:
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({"name": user['nickname'], "username": user['email'], "unique_id": user['sub'], "boats": None})
        client.put(new_user)
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f'https://{DOMAIN}'
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )


# -------------- FOR TESTING ON POSTMAN -----------------
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}


#  ============================ REST API ========================================


#  ----------------------------- USERS --------------------------------------------
@app.route('/users', methods=['GET'])
def user_get():
    if request.method == 'GET':
        if 'application/json' not in request.accept_mimetypes:
            return json.dumps(constants.not_acceptable_406), 406
        query = client.query(kind=constants.users)
        total_items = len(list(query.fetch()))
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
            e['self'] = request.base_url + '/' + str(e.key.id)
        output = {'total users': total_items, 'users': results}
        return json.dumps(output, sort_keys=True), 200
    else:
        return jsonify(error='Method not recognized'), 405


#  ----------------------------- BOATS --------------------------------------------

# A user is related to the boat as the owner
# Create a boat if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():
    if request.method == 'POST':
        if not request.is_json:
            return json.dumps(constants.unsupported_media_415), 415
        payload = verify_jwt(request)
        if payload:
            content = request.get_json()
            # check for all required attributes
            if "name" not in content or "type" not in content or "length" not in content:
                return json.dumps(constants.bad_request_400), 400
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({"name": content["name"], "type": content["type"],
                             "length": content["length"], "owner": payload["sub"], 'loads': []})
            client.put(new_boat)
            new_boat['id'] = new_boat.key.id
            new_boat['self'] = request.url + "/" + str(new_boat.key.id)
            new_boat['owner'] = payload["sub"]
            return json.dumps(new_boat), 201
    elif request.method == 'GET':
        if 'application/json' not in request.accept_mimetypes:
            return json.dumps(constants.not_acceptable_406), 406
        payload = verify_jwt(request)
        if payload:
            query = client.query(kind=constants.boats)
            query.add_filter('owner', '=', payload['sub'])
            total_items = len(list(query.fetch()))
            #  pagination
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            g_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = g_iterator.pages
            results = list(next(pages))
            if g_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + '?limit=' + str(q_limit) + '&offset=' + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
                e['self'] = request.base_url + '/' + str(e.key.id)
            output = {'total items': total_items, 'boats': results}
            if next_url:
                output['next'] = next_url
            constants.get_method = False
            return json.dumps(output, sort_keys=True), 200
    else:
        return jsonify(error='Method not recognized'), 405


@app.route('/boats/<boat_id>', methods=['DELETE', 'GET', 'PATCH', 'PUT'])
def boats_delete(boat_id):
    if boat_id == 'null':
        return json.dumps(constants.forbidden_403_null), 403
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if not boat:
        return json.dumps(constants.not_found_404_boat), 404
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        if payload:
            if payload['sub'] == boat['owner']:
                if not boat['loads']:
                    client.delete(boat_key)
                    return '', 204
                for loads in boat['loads']:
                    load_key = client.key(constants.loads, int(loads['id']))
                    load = client.get(key=load_key)
                    load['carrier'] = None
                    client.put(load)
                client.delete(boat_key)
                return '', 204
            else:
                return json.dumps(constants.forbidden_403), 403
    elif request.method == 'GET':
        payload = verify_jwt(request)
        if payload:
            if payload['sub'] == boat['owner']:
                if 'application/json' not in request.accept_mimetypes:
                    return json.dumps(constants.not_acceptable_406), 406
                boat["id"] = boat.key.id
                boat["self"] = str(request.url)
                return json.dumps(boat), 200
            else:
                return json.dumps(constants.forbidden_403), 403
    elif request.method == 'PATCH':
        payload = verify_jwt(request)
        if payload:
            if payload['sub'] == boat['owner']:
                if not request.is_json:
                    return json.dumps(constants.unsupported_media_415), 415
                content = request.get_json()
                if 'name' in content:
                    boat.update({'name': content['name']})
                    client.put(boat)
                if 'type' in content:
                    boat.update({'type': content['type']})
                    client.put(boat)
                if 'length' in content:
                    boat.update({'length': content['length']})
                    client.put(boat)
                boat['id'] = boat.key.id
                boat['self'] = request.url
                return json.dumps(boat), 200
            else:
                return json.dumps(constants.forbidden_403), 403
    elif request.method == 'PUT':
        payload = verify_jwt(request)
        if payload:
            if payload['sub'] == boat['owner']:
                if not request.is_json:
                    return json.dumps(constants.unsupported_media_415), 415
                content = request.get_json()
                if "name" not in content or "type" not in content or "length" not in content:
                    return json.dumps(constants.bad_request_400), 400
                boat.update({"name": content["name"], "type": content["type"],
                             "length": content["length"]})
                client.put(boat)
                boat['id'] = boat.key.id
                boat['self'] = request.url
                return json.dumps(boat), 200
            else:
                return json.dumps(constants.forbidden_403), 403
    else:
        return jsonify(error='Method not recognized'), 405

#  ----------------------------- LOADS --------------------------------------------

@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():
    if request.method == 'POST':
        if not request.is_json:
            return json.dumps(constants.unsupported_media_415), 415
        content = request.get_json()
        # check for all required attributes
        if "volume" not in content or "item" not in content or "creation_date" not in content:
            return json.dumps(constants.bad_request_400), 400
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({"volume": content["volume"], "item": content["item"],
                         "creation_date": content["creation_date"], "carrier": None})
        client.put(new_load)
        new_load["id"] = new_load.key.id
        new_load["self"] = str(request.url) + "/" + str(new_load.key.id)
        return json.dumps(new_load), 201
    elif request.method == 'GET':
        if 'application/json' not in request.accept_mimetypes:
            return json.dumps(constants.not_acceptable_406), 406
        query = client.query(kind=constants.loads)
        total_items = len(list(query.fetch()))
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))
        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.base_url + '/' + str(e.key.id)
        output = {'total items': total_items, 'loads': results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    else:
        return jsonify(error='Method not recognized'), 405

# TO DO: check if only a user can delete a load if it's on their boat

@app.route('/loads/<load_id>', methods=['DELETE', 'GET', 'PUT', 'PATCH'])
def load_delete_get(load_id):
    if load_id == 'null':
        return json.dumps(constants.forbidden_403_null), 403
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    if not load:
        return json.dumps(constants.not_found_404_load), 404
    elif request.method == 'DELETE':
        # check for load in boat loads, if load is in boat loads, set boat loads to none
        if load["carrier"] is None:
            client.delete(load_key)
            return '', 204
        boat_key = client.key(constants.boats, int(load['carrier']['id']))
        boat = client.get(key=boat_key)
        for load in boat['loads']:
            if load['id'] == int(load_id):
                boat['loads'].remove(load)
                client.put(boat)
        client.delete(load_key)
        return '', 204
    elif request.method == 'GET':
        if 'application/json' not in request.accept_mimetypes:
            return json.dumps(constants.not_acceptable_406), 406
        load["id"] = load.key.id
        load["self"] = str(request.url)
        return json.dumps(load), 200
    elif request.method == 'PATCH':
        if not request.is_json:
            return json.dumps(constants.unsupported_media_415), 415
        content = request.get_json()
        if 'volume' in content:
            load.update({'volume': content['volume']})
            client.put(load)
        if 'item' in content:
            load.update({'item': content['item']})
            client.put(load)
        if 'creation_date' in content:
            load.update({'creation_date': content['creation_date']})
            client.put(load)
        load['id'] = load.key.id
        load['self'] = request.url
        return json.dumps(load), 200
    elif request.method == 'PUT':
        if not request.is_json:
            return json.dumps(constants.unsupported_media_415), 415
        content = request.get_json()
        if "volume" not in content or "item" not in content or "creation_date" not in content:
            return json.dumps(constants.bad_request_400), 400
        load.update({"volume": content["volume"], "item": content["item"],
                     "creation_date": content["creation_date"]})
        client.put(load)
        load['id'] = load.key.id
        load['self'] = request.url
        return json.dumps(load), 200
    else:
        return jsonify(error='Method not recognized'), 405

#  ----------------------------- NON-USER ENTITIES RELATIONSHIP --------------------------------------------

@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def put_delete_loads(boat_id, load_id):
    load_key = client.key(constants.loads, int(load_id))
    boat_key = client.key(constants.boats, int(boat_id))
    load = client.get(key=load_key)
    boat = client.get(key=boat_key)
    # assign a load to a boat
    if request.method == 'PUT':
        payload = verify_jwt(request)
        if payload:
            if payload['sub'] == boat['owner']:
                if not boat or not load:
                    return json.dumps(constants.error_load_boat_404), 404
                if load['carrier'] is None:
                    if 'loads' in boat.keys():
                        boat['loads'].append({'id': load.id, 'self': request.root_url + 'loads/' + str(load.id)})
                        load['carrier'] = {'id': boat.id, 'name': boat['name'],
                                           'self': request.root_url + 'boats/' + str(boat.id)}
                    client.put(boat)
                    client.put(load)
                    return '', 204
                else:
                    return json.dumps(constants.error_load_403), 403
            else:
                return json.dumps(constants.forbidden_403), 403
    # delete a load from a boat without deleting the load
    elif request.method == 'DELETE':
        payload = verify_jwt(request)
        if payload:
            if payload['sub'] == boat['owner']:
                if not load or not boat:
                    return json.dumps(constants.error_no_load_boat_404), 404
                load_count = 0
                for loads in boat['loads']:
                    if loads['id'] == int(load_id):
                        load_count += 1
                        boat['loads'].remove(loads)
                if load_count == 0:
                    return constants.error_no_load_boat_404, 404
                load['carrier'] = None
                client.put(boat)
                client.put(load)
                return '', 204
            else:
                return json.dumps(constants.forbidden_403), 403
    else:
        return jsonify(error='Method not recognized'), 405






if __name__ == '__main__':
    app.run(host='127.0.0.1', port=3000, debug=True)
