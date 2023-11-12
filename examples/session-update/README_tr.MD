# Repeat And Replace - Session Update

Bu readme.md dosyası, Repeat And Replace eklentisinin bir örneği olarak kullanılabilecek basit bir Flask uygulamasını ve ilgili konfigürasyon dosyasını açıklar. Bu örnek, bir oturum yönetimi senaryosunu simgeler ve eklentinin nasıl yapılandırılacağını, çalışma mantığını ve kullanımını ayrıntılı bir şekilde açıklar.

## Flask Uygulaması

Öncelikle, Flask uygulamasının nasıl çalıştığını inceleyelim. Bu uygulama, oturum yönetimi için bir örnek sunar. Ana işlevleri şunlardır:

- Kullanıcı adı ve şifre doğrulaması yapma.
- Oturum açma ve oturumu koruma.
- Oturumu sonlandırma.

Uygulamanın çalışma mantığı basittir. `app.py` adında bir Python dosyasında uygulama bulunur. İşte uygulamanın temel yapısı:

```python
from flask import Flask, request, session, jsonify
from datetime import timedelta

app = Flask(__name__)

app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=10)

# Oturum yönetimi için kullanıcı girişi
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Kullanıcı adı ve şifre doğrulaması yapılabilir
    if username == 'user' and password == 'password':
        session['logged_in'] = True
        return jsonify(message='Başarıyla giriş yaptınız.'), 200
    else:
        return jsonify(message='Kullanıcı adı veya şifre yanlış.'), 401

# Oturum korumalı verilere erişim
@app.route('/protected', methods=['GET'])
def protected():
    if 'logged_in' in session and session['logged_in']:
        return jsonify(message='Bu özel verilere erişebilirsiniz.'), 200
    else:
        return jsonify(message='Oturum açmanız gerekiyor.'), 401

# Oturumu sonlandırma
@app.route('/logout', methods=['GET'])
def logout():
    session['logged_in'] = False
    return jsonify(message='Oturumunuz kapatıldı.'), 200

if __name__ == '__main__':
    app.run(debug=True)
```

Bu Flask uygulaması, `/login` endpoint'inde kullanıcı girişi yapar, `/protected` endpoint'inde oturumu korumalı verilere erişim sağlar ve `/logout` endpoint'inde oturumu sonlandırır.

## Config Dosyası Oluşturma

Repeat And Replace eklentisini kullanarak bu Flask uygulamasını test etmek için aşağıdaki adımları izleyebilirsiniz. İşte adım adım nasıl bir config dosyası oluşturacağınız:

1. **Config Dosyasının İskeletini Oluşturma**

   Öncelikle, config dosyasının genel yapısını oluşturun. Bu yapı, dosyanın temel bölümlerini içerir:

   ```yaml
   name: session-update

   matcher:
     request:
       - - from: request_header
           contains:
             - "GET /protected HTTP/1.1"
     response:
       - - from: response_header
           contains:
            - "HTTP/1.1 401 UNAUTHORIZED"

   from:
     - Repeater

   repeat:
     - raw_request:
       - |
         POST /login HTTP/1.1
         Host: 127.0.0.1:5000
         # Diğer HTTP başlıkları...
         {"username":"user","password":"password"}

       service:
         protocol: http
         port: 5000
         host: 127.0.0.1
   ```

   Bu yapı, config dosyasının temel bölümlerini içerir. "name" bölümünde dosyanın adını, "matcher" bölümünde isteklerin ne zaman eşleşeceğini tanımlayan koşulları, "from" bölümünde hangi Burp Suite modüllerinden gelen trafikleri izleyeceğinizi, "repeat" bölümünde nasıl bir isteği tekrarlayacağınızı belirtirsiniz.

2. **Matcher Bölümünü Tanımlama**

   Matcher bölümü, eklentinin ne zaman devreye gireceğini tanımlayan koşulları içerir. Örneğin, oturum süresi dolduğunda otomatik olarak yeni bir oturum oluşturmak istediğimizde bu koşulları kullanırız.

   ```yaml
   matcher:
     request:
       - - from: request_header
           contains:
             - "GET /protected HTTP/1.1"
     response:
       - - from: response_header
           contains:
            - "HTTP/1.1 401 UNAUTHORIZED"
   ```

   Bu örnekte, isteğin `GET /protected` olduğunda ve yanıtın `HTTP/1.1 401 UNAUTHORIZED` olduğunda eklentinin devreye gireceğini belirtiyoruz.

3. **Modül Kaynağını Tanımlama**

   `from` bölümünde, eklentinin hangi Burp Suite modüllerinin işlemlerini izleyeceğini belirtiriz. Biz bu örnekte "Repeater" modülünü kullanıyoruz:

   ```yaml
   from:
     - Repeater
   ```

   Bu, eklentinin yalnızca Repeater modülünden gelen istekleri işleyeceğini gösterir.

4. **İstekleri Tekrarlama**

   `repeat` bölümü, bir isteğin nasıl tekrarlanacağını tanımlar. İstekler Burp Suite içindeki "Repeat And Replace" özelliği ile kopyalanabilir. Örnekte, giriş yapma isteğini tekrarlamak için aşağıdaki gibi bir yapı kullanırız:

   ```yaml
   repeat:
     - raw_request:
       - |
         POST /login HTTP/1.1
         Host: 127.0.0.1:5000
         # Diğer HTTP başlıkları...
         {"username":"user","password":"password"}

       service:
         protocol: http
         port: 5000
         host: 127.0.0.1
   ```

   Bu bölümde, giriş yapma isteğini oluşturan raw_request ve hedef servisin konfigürasyonunu belirtiyoruz.

5. **Bilgi Çıkarma ve Değiştirme**

   Eklenti, isteklerin ve yanıtların içeriğini değiştirmek için kullanılabilir. Örnekte, oturum bilgisini çıkartmak ve tekrar kullanmak için aşağıdaki yapıyı kullanırız:

   ```yaml
   extractor:
     - name: session
       start: "Set-Cookie: session="
       end: ";"
       regex: false

   replacer:
     - replace_with: session
       start: "Cookie: session="
       end: ";"
       regex: false
   ```

   Bu bölümde, oturum bilgisini çıkartmak için extractor ve çıkartılan oturumu yeniden kullanmak için replacer tanımlarız.

6. **Sürekli Güncelleme**

   Eğer `continuousupdate` değeri `true` olarak ayarlanırsa, eklenti, her bir istek eşleştiğinde `repeat` bölümündeki istekleri tekrarlayacak ve yanıtları izleyecektir. Yanıtlar içinde belirtilen hata görüldüğünde veya oturum süresi dolarsa yeni bir oturum üretilecektir. Bu sayede, aynı oturum bir süre boyunca (oturum süresi dolana kadar) tekrar kullanılır. Bu özellik, sürekli güncelleme gerektiren senaryolar için kullanışlıdır.

   ```yaml
   continuousupdate: true
   ```

Bu adımları takip ederek, Repeat And Replace eklentisini kullanarak Flask uygulamanızı test etmek için bir config dosyası oluşturabilirsiniz. Config dosyasının yapısını anladığınızdan emin olmak için bu örneği inceleyebilirsiniz.

Bu örnek, Repeat And Replace eklentisinin temel kullanımını göstermektedir. Daha karmaşık senaryolar için config dosyasını özelleştirebilirsiniz.
