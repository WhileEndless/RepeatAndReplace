# Repeat And Replace - Standard Repeat Senaryosu

Bu belge, Repeat And Replace eklentisi için bir Flask uygulamasını ve ilişkili konfigürasyon dosyasını detaylı bir şekilde anlatmaktadır. Flask uygulaması, bir dizi API endpointi içerir ve bu endpointler arasında token bazlı bir akış sağlar.

## Flask Uygulaması ve Çalışma Mantığı

Uygulama `app.py` adlı Python dosyasında bulunur ve bir dizi endpoint içerir:

- **`/test1` Endpointi:** Bir GET isteği alır ve `test2` ve `deger` için rastgele tokenlar üretir.
- **`/test2` Endpointi:** Bir POST isteği alır, gelen tokenları doğrular ve `test3` için yeni bir token üretir.
- **`/test3`, `/test4`, `/test5` Endpointleri:** Benzer şekilde, bir POST isteği alır, gelen tokenları doğrular ve bir sonraki endpoint için yeni bir token üretir.

Bu zincirleme akış, token tabanlı istekleri ve token doğrulamalarını nasıl yöneteceğimizi gösterir.

## Config Dosyası Oluşturma Süreci

### 1. Config Dosyasının İskeletini Oluşturma

Öncelikle, `standard-repeat.yaml` adında bir config dosyası oluşturarak başlayalım:

```yaml
name: "standard repeat"

matcher: []

from: []

repeat: []

extractor: []

replacer: []

continuousupdate: false
```

### 2. Matcher Bölümünü Tanımlama

Matcher bölümü, eklentinin hangi koşullar altında devreye gireceğini tanımlar. Burada, `POST /test5` isteği üzerinde odaklanıyoruz çünkü bu, pentest sırasında izlediğimiz beş adımlı istek zincirinin son adımını temsil eder:

```yaml
matcher:
  - - from: request_header
      contains:
        - POST /test5
```

### 3. Modül Kaynağını Tanımlama

`from` bölümü, eklentinin hangi Burp Suite modüllerinin isteklerini izleyeceğini belirler. Bu örnekte "Repeater", "Scanner" ve "Intruder" modülleri seçiliyor:

```yaml
from:
  - Repeater
  - Scanner
  - Intruder
```

### 4. İstekleri Tekrarlama

`repeat` bölümünde, ilk iki adım için gerekli olan istekler tanımlanır. Bu, zincirleme işlemin nasıl gerçekleşeceğini belirler:

```yaml
repeat:
  # İlk adım: /test1 endpointine GET isteği gönderilir
  - service:
      host: "localhost"
      port: 5000
      protocol: http
    raw_request:
      - |
        GET /test1 HTTP/1.1
        Host: 127.0.0.1:5000
        # Diğer HTTP başlıkları...
    extractor:
      - name: token2
        start: "\"token\": \""
        end: "\""
        regex: false
      - name: deger
        start: "\"deger\": \""
        end: "\""
        regex: false

  # İkinci adım: /test2 endpointine POST isteği gönderilir
  - service:
      host: "localhost"
      port: 5000
      protocol: http
    raw_request:
      - |
        POST /test2?token={{token2}} HTTP/1.1
        Host: 127.0.0.1:5000
        Content-Type: application/json
        # Diğer HTTP başlıkları...
        {"deger":"{{deger}}"}
```

### 5. Sonraki Adımlar ve Sürekli Güncelleme

Sonraki adımlar için benzer extractor ve replacer tanımlamaları yapılabilir. Her adım, önceki adımdan gelen bilgileri kullanarak yeni istekler oluşturur. `continuousupdate` değeri bu senaryoda `false` olarak ayarlanmıştır, bu da sürekli güncelleme olmayacağı anlamına gelir.

Bu adımları takip ederek, Repeat And Replace eklentisi için bir Flask uygulamasını ve konfigürasyon dosyasını oluşturabilir ve bu örneği kendi ihtiyaçlarınıza göre özelleştirebilirsiniz. Bu örnek, eklentinin zincirleme ve koşullu istek işleme yeteneklerini detaylı bir şekilde göstermektedir.
