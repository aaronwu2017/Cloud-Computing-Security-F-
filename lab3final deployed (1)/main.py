import sys
sys.path.insert(0, 'libs')
import flask
import json
import uuid
import requests
import os 
import base64
from datetime import datetime
from google.cloud import datastore
from datetime import timedelta
from lib.pyscrypt import hash
#from lib.pybcrypt2 import pybcrypt2


datastore_client = datastore.Client()
if os.getenv('GAE_EW','').startswith('standard'):
    ROOT= datastore_client.key('Entities','root')
else:
    ROOT=datastore_client.key('Entities','dev')

app = flask.Flask(__name__)

secret =datastore_client.get(datastore_client.key('secret', 'oidc'))['client-secret']
stateg = "0"
nonceg="0"
app.secret_key="hello"
app.permanent_session_lifetime=timedelta(minutes=1)



 
@app.route('/event',methods=['POST',"GET"])
def new_event():
    '''put a new event in the databse, then redirect the user to the homepage.'''

#    data = flask.request.json
#    user = flask.session["user"]
#    pkey= datastore_client.key('user', user,parent=ROOT);

#    print(pkey);
#    key=datastore_client.key('event', parent=pkey)
#    entity = datastore.Entity(key=datastore_client.key('event', parent=pkey))
#    print("222")
    
#    print(key)
#    entity.update({
#        'name':data['name'],
#        'date':data['date'],
#    })
#    datastore_client.put(entity)
    
#    return flask.redirect('/')
    print("pkeynewnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn");
    user = get_user(flask.request.cookies.get('sess'))
    if not user:
        return flask.redirect(flask.url_for("login"))

    data = flask.request.json
    ke =datastore_client.key("user", user.key.name, parent=ROOT)
    entity = datastore.Entity(key=datastore_client.key("event", parent=ke))
    entity.update({
        'name': data['name'],
        'date': data['date'],
    })
    datastore_client.put(entity)
    return ''

@app.route('/events',methods=["POST","GET"])
def events():
    '''return a json object. events contains all events as a list'''
  
#    if "user" in flask.session:
 #       user = flask.session["user"]
  #  else:
   #     return flask.render_template("login.html")
 #   print(user);
 #   user = flask.session["user"]
 #   pkey= datastore_client.key('user', user,parent=ROOT);
 #   query = datastore_client.query(kind='event',ancestor=pkey)
 #   vals=query.fetch();
 #   return flask.jsonify(
 #       {
 #           'events':[{'name':v['name'], 'date':v['date'],'id':v.id}
 #                       for v in vals],
 #           'error':None,
 #       }
 #   ) 
    user = get_user(flask.request.cookies.get('sess'))
   # if not user:
   #     return flask.jsonify({
   #         'error': 'no session',
   #         'redirect': '/login.html',
   #     })
    if not user:
        return flask.redirect(flask.url_for("login"))
  
    ke =datastore_client.key("user", user.key.name, parent=ROOT)
    query = datastore_client.query(kind="event", ancestor=ke)
    vals = query.fetch()
    print("111")
    return flask.jsonify(
        {
            'events':[{'name':v['name'], 'date':v['date'],'id':v.id}
                        for v in vals],
            'error':None,
        }
    ) 



@app.route('/')
def root():
    '''return index.html.'''
 #   if "user" in flask.session:
 #       return flask.send_from_directory('static','index.html')
 #   else:
 #       return   flask.redirect(flask.url_for("login"))
 #       return flask.render_template("login.html")
    user1 = get_user(flask.request.cookies.get('sess'))
     
    
    print("home")
    if not user1:
        return flask.redirect('/login')
    return flask.send_from_directory('static', 'index.html')
#    if "user" in flask.session:
        
#        return flask.send_from_directory('static','index.html')
 #   else:
 #       return flask.redirect(flask.url_for("login"))
 #   print("fcc")
 #   return ""



@app.route('/event/<int:event_id>',methods=['DELETE','GET'])
def del_event(event_id):
    '''return empty string. delete a specific event in the database'''
  #  user = flask.session["user"]
  #  pkey= datastore_client.key('user', user,parent=ROOT);
  #  e = datastore_client.key('event', event_id,parent=pkey)

   # datastore_client.delete(e)
    user = get_user(flask.request.cookies.get('sess'))
    if not user:
        return flask.redirect('/')

    ukey = datastore_client.key("user", user.key.name, parent=ROOT)

    datastore_client.delete(datastore_client.key("event", event_id, parent=ukey))
    return ''



@app.route('/login', methods = ["POST","GET"])
def login():
    
    if flask.request.method=="POST":
       
        user = flask.request.form["nm"]
        
        query = datastore_client.query(kind='user',ancestor=ROOT)
        pp=flask.request.form["password"]
        h = hash(password = pp.encode(), 
                       salt = b"seasalt", 
                       N = 1024, 
                       r = 1, 
                       p = 1, 
                       dkLen = 256)
        query.add_filter('name', '=', user)
        query.add_filter('password', '=', h)
        print(h)
        #result[1]
        results = list(query.fetch())
        if(not results):
            return flask.redirect(flask.url_for("login"))
        print(results)
      #  if(val[name]==user&&)
      #  flask.session["user"] = user
        sess_tok = createsession(user)
        resp = flask.redirect('/')
        resp.set_cookie('sess', sess_tok)
        
       
        return  resp
    else:
#        if "user" in flask.session:
            
 #           return flask.redirect('/')
        ramn = str(uuid.uuid4())
        rams=str(uuid.uuid4())
 #       flask.session["nonce"] = ramn
 #       flask.session["state"] =rams
        stateg = rams
        nonceg=ramn
        #ntok= new_session(ramn)
        #stok=new_session(rams)



        res = flask.send_from_directory('static','login.html')
      #  res.set_cookie('redir','https://8080-47504a2c-f2e8-4340-ad1d-230fa7f2c882.us-east1.cloudshell.dev/re')
        res.set_cookie('redir','https://gothic-province-290512.uc.r.appspot.com/re')
     #   res.set_cookie('redir','https://8080-cs-213677566742-default.us-east1.cloudshell.dev/re')

        res.set_cookie('state',rams)
        res.set_cookie('nonce',ramn)
        print("fffff")
        
        return res



@app.route('/register', methods = ["POST","GET"])
def register():
    
    name = flask.request.form["newname"]
    password=flask.request.form["newpassword"]
   
    entity = datastore.Entity(key=datastore_client.key('user',name, parent=ROOT))
    hashed = hash(password = password.encode(), 
                       salt = b"seasalt", 
                       N = 1024, 
                       r = 1, 
                       p = 1, 
                       dkLen = 256)
  #  final = hashed.decode(encoding='UTF-8').strip()
  #  print(password.encode())
   
  #  print(hash(password = b"password", 
  #                     salt = b"seasalt", 
  #                     N = 1024, 
  #                     r = 1, 
  #                     p = 1, 
  #                     dkLen = 256))
    entity.update({
        'name':name,
        'password':hashed,
    })

   
    datastore_client.put(entity)
    sess_tok = createsession(name)
    resp = flask.redirect('/')
    resp.set_cookie('sess', sess_tok)
    return resp
#@app.route("/user")
#def user():
#    if "user" in flask.session:
#        user = flask.session["user"]
#        return flask.send_from_directory('static','index.html')
      #  return flask.render_template("index.html")

#    else:
#        return flask.redirect(flask.url_for("login"))



@app.route("/logout",methods = ["POST","GET"])
def logout1():
   # flask.session.pop("user",None)

    tok = flask.request.cookies.get('sess')
    k=datastore_client.key("session", tok, parent=ROOT)
    datastore_client.delete(k)
    resp = flask.redirect(flask.url_for("login"))
    resp.delete_cookie('sess')
    print("d2222222222222222e")
    return resp

@app.route("/oidcauth",methods = ["POST","GET"])
def au():
    a =  flask.request.args['code']

    return a

@app.route("/re")
def re():
    
    a = flask.request.args['code']
    b= flask.request.args['state']
    print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    print(flask.request.cookies.get('state'))
    if(b!=flask.request.cookies.get('state')):
        #thi
        return "state is false"
    response = requests.post("https://www.googleapis.com/oauth2/v4/token",
    {"code": a,
 #   "client_id": "748526789056-acniorol1ncvnr56rmpb0gae51glano6.apps.googleusercontent.com",
    "client_id": "748526789056-f53eap07105dbjj4dskvem9942htce6m.apps.googleusercontent.com",
    
  #  "client_secret": "UTmYcvh8ntQ2lZr04znqS6Io",
  #  "client_secret": "ObUU1h1aqOstR8FE_eTE5DZI",
    "client_secret": secret,
  #  "redirect_uri": "https://8080-47504a2c-f2e8-4340-ad1d-230fa7f2c882.us-east1.cloudshell.dev/re",
  # "redirect_uri": "https://8080-cs-213677566742-default.us-east1.cloudshell.dev/re",
    
    "redirect_uri": "https://gothic-province-290512.uc.r.appspot.com/re",
    "grant_type": "authorization_code"})
    jso = response.json()
    print(jso)
    token = jso['id_token']
    _, body, _ = token.split('.')
    body += '=' * (-len(body) % 4)
    tt=body.encode('utf-8')
    claims = json.loads(base64.urlsafe_b64decode(tt))
    print(claims)
    sub = claims['sub']
   
#thiss
#    if(flask.session["nonce"]!=claims['nonce']):
#        print(flask.session["state"])
#        print(flask.session["nonce"])
#        return "a"
    if(flask.request.cookies.get('nonce')!=claims['nonce']):
       
        return "nonce is false"
    entity = datastore.Entity(key=datastore_client.key('user',sub, parent=ROOT))

    entity.update({
        'name': sub,
    })
   # print(ram)

    print(claims)
#thisssssssssssssssssssssssssssssssssssssssssssssssssssssss
 #   flask.session["user"] = sub
  #  datastore_client.put(entity)
  #   return flask.redirect('/')
    
    datastore_client.put(entity)
    tok = createsession(sub)
    resp=flask.redirect('/')
    resp.set_cookie('sess',tok)

    
    return resp

#    return sub

#def new_session(username):
    

#    tok = str(uuid.uuid4())
    
#    skey = datastore_client.key("session",tok,parent=ROOT)
#    sess = datastore.Entity(key=skey)
#    sess.update({
#        'username': username,
        
#    })
#    datastore_client.put(sess)

#    return tok



def createsession(username):
    

    tok = str(uuid.uuid4())
    

    sess = datastore.Entity(key=sess_key(tok))
    sess.update({
        'username': username,
        
    })
    datastore_client.put(sess)

    return tok

def sess_key(tok):
    return datastore_client.key("session", tok, parent=ROOT)

def get_user(sess_str):
    if not sess_str:
        return None
    sk = datastore_client.key("session", sess_str, parent=ROOT)
    sess = datastore_client.get(sk)
    if not sess:
        return None
    username = sess.get('username')
    uk = datastore_client.key("user", username, parent=ROOT)

    user = datastore_client.get(uk)

    return user

if __name__=='__main__':
    app.run(host='::',port=8080,debug=True)


