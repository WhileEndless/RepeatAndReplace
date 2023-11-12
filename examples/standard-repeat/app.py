from flask import Flask, jsonify, request
import uuid

app = Flask(__name__)

tokens = {
    'test2': None,
    'test3': None,
    'test4': None,
    'test5': None,
    'deger':None
}

@app.route('/test1', methods=['GET'])
def test1():
    tokens['test2']=str(uuid.uuid4())
    tokens['deger']=str(uuid.uuid4())
    return jsonify(token=tokens['test2'],deger=tokens['deger'])

@app.route('/test2', methods=['POST'])
def test2():
    
    data = request.get_json()
    print(data)
    if request.args.get('token')!=tokens['test2']:
        tokens['test2']=None
        return "Error"
    if 'deger' not in data or data['deger']!=tokens['deger']:
        tokens['test2']=None
        tokens['deger']=None
        return "Error"
    tokens['test2']=None
    tokens['test3']=str(uuid.uuid4())
    return jsonify(token=tokens['test3'])

@app.route('/test3', methods=['POST'])
def test3():
    data = request.get_json()
    if data is None or 'token' not in data or data['token']!=tokens['test3']:
        tokens['test3']=None
        return "Error"
    
    tokens['test3']=None
    tokens['test4']=str(uuid.uuid4())
    return jsonify(token=tokens['test4'])

@app.route('/test4', methods=['POST'])
def test4():
    data = request.get_json()
    if data is None or 'token' not in data or data['token']!=tokens['test4']:
        tokens['test4']=None
        return "Error"
    
    tokens['test4']=None
    tokens['test5']=str(uuid.uuid4())
    return jsonify(token=tokens['test5'])

@app.route('/test5', methods=['POST'])
def test5():
    
    data = request.get_json()
    if data is None or 'token' not in data or data['token']!=tokens['test5']:
        tokens['test5']=None
        return "Error"
    tokens['test5']=None
    return "Successful"

if __name__ == '__main__':
    app.run(debug=True)
