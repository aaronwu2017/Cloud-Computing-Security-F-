import sys
sys.path.insert(0, 'libs')
import flask
import json
import os 
import uuid
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

app.secret_key="hello"
#app.permanent_session_lifetime=timedelta(minutes=60)



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
#    user="aaa"
#    if "user" in flask.session:
 #       user = flask.session["user"]
  #  else:
   #     return flask.render_template("login.html")
    print("events--")
#    user = flask.session["user"]
#    pkey= datastore_client.key('user', user,parent=ROOT);
#    
#      vals=query.fetch();
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
"""
    if "user" in flask.session:
        
        return flask.send_from_directory('static','index.html')
    else:
        return flask.redirect(flask.url_for("login"))
    print("fcccccc")
    return ""
 """ 


@app.route('/event/<int:event_id>',methods=['DELETE','GET'])
def del_event(event_id):
    '''return empty string. delete a specific event in the database'''
#    user = flask.session["user"]
#    pkey= datastore_client.key('user', user,parent=ROOT);
#    e = datastore_client.key('event', event_id,parent=pkey)

#    datastore_client.delete(e)
#    return ''
    user = get_user(flask.request.cookies.get('sess'))
    if not user:
        return flask.redirect('/')

    ukey = datastore_client.key("user", user.key.name, parent=ROOT)
    print("dededededdededededededededeede");
    datastore_client.delete(datastore_client.key("event", event_id, parent=ukey))
    return ''



@app.route('/login', methods = ["POST","GET"])
def login():
    
    if flask.request.method=="POST":

#       flask.session.permanent=True
#        user = flask.request.form["nm"]
        
#        query = datastore_client.query(kind='user',ancestor=ROOT)
#        pp=flask.request.form["password"]
#        h = hash(password = pp.encode(), 
#                       salt = b"seasalt", 
#                       N = 1024, 
#                       r = 1, 
#                       p = 1, 
#                       dkLen = 256)
#        query.add_filter('name', '=', user)
#        query.add_filter('password', '=', h)
#        print(h)
        #result[1]
#        results = list(query.fetch())
#        if(not results):
#            return flask.redirect(flask.url_for("login"))
#        print(results)
      #  if(val[name]==user&&)
#        flask.session["user"] = user 
        username = flask.request.form['nm']
        pp = flask.request.form['password']
        query = datastore_client.query(kind='user',ancestor=ROOT)
        h = hash(password = pp.encode(), 
                       salt = b"seasalt", 
                       N = 1024, 
                       r = 1, 
                       p = 1, 
                       dkLen = 256)
        query.add_filter('name', '=', username)
        query.add_filter('password', '=', h)
        print(h)
        #result[1]
        results = list(query.fetch())
        if(not results):
            return flask.redirect(flask.url_for("login"))



        sess_tok = createsession(username)
      #  logging.info("new session: %r", sess_tok)
        print("q222")
        resp = flask.redirect('/')
        resp.set_cookie('sess', sess_tok)
        return resp
    else:
        return flask.send_from_directory('static','login.html')



@app.route('/register', methods = ["POST"])
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
    print("register")

    datastore_client.put(entity)
    tok = createsession(name)
    resp=flask.redirect('/')
    resp.set_cookie('sess',tok)

    
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
def logout():
   # flask.session.pop("user",None)
#    del_session()
    tok = flask.request.cookies.get('sess')
    k=datastore_client.key("session", tok, parent=ROOT)
    datastore_client.delete(k)
    resp = flask.redirect(flask.url_for("login"))
    resp.delete_cookie('sess')
    print("d2222222222222222e")
    return resp



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

