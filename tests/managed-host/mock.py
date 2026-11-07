import http.server, ssl, json, pathlib, time, uuid, threading
from urllib.parse import urlparse, parse_qs
ROOT=pathlib.Path('/work')
LOCK=threading.Lock()
def write(name,data):
    tmp=ROOT/(name+'.tmp')
    tmp.write_text(json.dumps(data));tmp.replace(ROOT/name)
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def reply(self,data,status=200):
        encoded=json.dumps(data,separators=(',',':')).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
    def do_GET(self):
        path=urlparse(self.path).path
        if '/releases/download/' in path:
            version=path.split('/releases/download/')[1].split('/')[0]
            data=(ROOT/version).read_bytes();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
        if path.endswith('/server/config'):
            node_id=int(parse_qs(urlparse(self.path).query).get('node_id',['1'])[0])
            payload={'protocol':'anytls','listen_ip':'127.0.0.1','server_port':14442+node_id,'network':'tcp','network_settings':{},'tls':1,
              'tls_settings':{'cert_mode':'self','server_name':'localhost','cert_file':'/etc/v2node/local.cer','key_file':'/etc/v2node/local.key'},
              'routes':[],'base_config':{'pull_interval':2,'push_interval':60,'device_online_min_traffic':0,'node_report_min_traffic':0}}
            if self.headers.get('Authorization')=='Bearer '+'d'*64:
                if (ROOT/'config-target.json').exists():self.reply(json.loads((ROOT/'config-target.json').read_text()))
                else:self.reply({'schema_version':1,'mode':'bootstrap','revision':0,'attempt':0,'credential_generation':1,'payload':payload})
            else:self.reply(payload)
            return
        if path.endswith('/user'):self.reply({'users':[{'id':1,'uuid':'11111111-1111-4111-8111-111111111111','speed_limit':0,'device_limit':0,'traffic_budget':False}]});return
        if path.endswith('/alivelist'):self.reply({'alive':{}});return
        self.reply({'data':True})
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))) or '{}')
        path=urlparse(self.path).path
        with LOCK:
            if path.endswith('/config/ack'):write('config-ack.json',body);self.reply({'data':{'accepted':True}});return
            if path.endswith('/enroll'):self.reply({'data':{'host_id':body['host_id'],'host_token':'a'*64,'service_report_token':'b'*64,'protocol_version':2,'credential_generation':1}});return
            if path.endswith('/heartbeat'):write('heartbeat.json',body);self.reply({'data':{'accepted':True,'server_time':int(time.time())}});return
            if path.endswith('/instance-status'):write('business.json',body);self.reply({'data':{'accepted':True,'server_time':int(time.time())}});return
            if path.endswith('/claim'):
                pending=json.loads((ROOT/'control.json').read_text()) if (ROOT/'control.json').exists() else None
                result=json.loads((ROOT/'result.json').read_text()) if (ROOT/'result.json').exists() else None
                if pending and result and pending['id']==result['operation_id']:pending=None
                self.reply({'data':pending});return
            if path.endswith('/begin'):self.reply({'data':{'begin_id':str(uuid.uuid4()),'authorized_until':int(time.time())+30}});return
            if path.endswith('/progress'):write('progress.json',body);self.reply({'data':{'accepted':True}});return
            if path.endswith('/result'):write('result.json',body);self.reply({'data':{'accepted':True}});return
            self.reply({'data':True})
def serve(port):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/work/local.crt','/work/local.key');server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
threading.Thread(target=serve,args=(443,),daemon=True).start()
serve(8443)
