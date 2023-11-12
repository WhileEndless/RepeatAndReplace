# Repeat And Replace

## Genel Bakış
Repeat And Replace, HTTP istek ve yanıtlarını desen eşleştirme yoluyla analiz eden ve belirli kriterlere bağlı olarak içeriği değiştirip yeniden gönderen bir Burp Suite eklentisidir. Geliştiriciler ve güvenlik araştırmacıları için tasarlanmıştır ve manuel iş akışlarını otomatize ederek zaman tasarrufu sağlamak ve hata olasılığını azaltmak amacı taşır.

## Özellikler
- **Desen Eşleştirme:** HTTP istek ve yanıtlarında tanımlanan kalıpları otomatik olarak tespit eder.
- **Modüllerden İstekleri İşleme:** Belirli Burp Suite modüllerinden gelen isteklerin işlenmesi.
- **İstek Tekrarlama:** Ayar dosyasında belirtilen sırayla ve servis ayarlarına göre HTTP isteklerinin tekrarlanması.
- **Bilgi Çıkarma ve Değiştirme:** İstek veya yanıtlardan bilgi çıkarma ve bu bilgilerle belirli metinleri değiştirme.
- **Otomatik ve Sürekli Güncelleme:** Yapılandırma dosyasındaki değişikliklerin eklenti tarafından otomatik olarak algılanıp uygulanması.
- **Oturum Yönetimi:** Bağımsız oturum yönetimi ve bağlantı izolasyonu.
- **Akış Kontrolü:** İstek işleme sırası ve eylemlerin düzenli akışını sağlama.
- **Durum Yönetimi ve Günlük Kaydı:** İşlemlerin durumunu izleme ve loglama.

## Kullanım Senaryoları
Repeat And Replace, aşağıdaki gibi senaryolarda kullanılmak üzere idealdir:
- Penetrasyon testlerinde tekrarlanan ve düzenli istek gönderme ihtiyacında.
- Karmaşık oturum mekanizmaları gerektiren uygulamaların test edilmesinde.
- İstek ve yanıtlarda bulunan belirli veri parçalarının çıkarılması ve yeniden kullanılmasında.
- Otomatik ve sürekli yapılandırma değişikliklerinin uygulanmasında.

---

# Kurulum

## Yapılandırma
1. `snakeyaml.jar` dosyasını indirin. Bu kütüphane, YAML dosyalarını eklentinin anlayabileceği bir formata dönüştürmek için gereklidir.
   
2. Burp Suite'i açın ve "Extender" sekmesine gidin.

3. "Options" alt sekmesini bulun ve "Java Environment" alanına `snakeyaml.jar` dosyasının yolunu ekleyin. Bu işlem, eklentinin YAML dosyalarını işleyebilmesi için gereklidir.

## Eklentinin Yüklenmesi
1. Burp Suite içinde "Extender" sekmesine geri dönün.

2. "Extensions" alt sekmesine geçin ve "Add" butonuna tıklayın.

3. Açılan diyalog penceresinde, "Extension Type" olarak "Java" seçeneğini belirleyin.

4. "Select file..." butonuna tıklayarak, "Repeat And Replace" eklentisine ait `.jar` uzantılı dosyayı seçin.

5. Eklentiyi seçtikten sonra "Next" veya "Finish" butonuna tıklayarak kurulum işlemini tamamlayın.

Kurulum tamamlandıktan sonra, Repeat And Replace eklentisi Burp Suite içerisinde aktif hale gelmiş olacak ve kullanıma hazır durumda olacaktır.

Yapılandırma dosyasının nasıl hazırlanacağı ve eklentinin nasıl kullanılacağına dair daha fazla bilgi için, lütfen eklenti dokümantasyonuna başvurun.

# Config Dosyası Oluşturma 

## Config Dosyasının İskeletini Oluşturma
Öncelikle config dosyasının genel yapısını kurarak başlayın. Bu yapı, dosyanın temel bölümlerini oluşturur.

```yaml
name: uygulama_adi_config

matchers: []

from: []

repeat: []

replacer: []
```

### Matcher Bölümünü Tanımlama

Matcher bölümü, eklentinin ne zaman devreye gireceğini tanımlayan koşulları içerir. Matcher yapısında, en içteki liste (`AND` mantığı ile çalışan) koşulların hepsinin aynı anda karşılanmasını gerektirirken, en dıştaki liste (`OR` mantığı ile çalışan) alternatif koşullar grubunu temsil eder.

Her bir "AND" grubu (`-` ile başlayan iç listeler), eklentinin o grup içindeki tüm koşulları aynı anda karşılaması gerektiğini ifade eder. Bir dış liste içinde birden fazla "AND" grubu varsa, bu gruplardan herhangi birinin koşulları karşılandığında ("OR" mantığı ile) eklenti devreye girer.

```yaml
matchers:
  # Bu liste "OR" mantığı ile çalışır - Listelenen gruplardan herhangi biri eşleşirse matcher devreye girer.
  - # Aşağıdaki liste "AND" mantığı ile çalışır - Bu gruptaki tüm koşulların karşılanması gerekir.
    - from: request_header
      contains:
        - 'POST /test5'
      regex: false
    - from: response_body
      contains:
        - 'Error'
  - # Bu da başka bir "AND" grubudur ve yukarıdaki grupla "OR" ilişkisi içindedir.
    - from: request_body
      contains:
        - '"token": "'
    - from: response_header
      contains:
        - '403'
```

Matcher yapısında her `contains` listesi "AND" mantığı ile değerlendirilir; yani, bir `from` kaynağından gelen veri, `contains` listesinde belirtilen tüm değerleri içermelidir. En dıştaki liste ise bu grupların her birinin birer alternatif olduğunu ve sadece bir grupla eşleşmenin yeterli olduğunu ifade eder.

Regex seçeneği her bir eşleşme kuralında opsiyonel olarak belirtilebilir. Eğer belirli bir eşleşme için düzenli ifadeler kullanmak isteniyorsa `regex: true` olarak belirtilir, aksi takdirde bu alanı atlayabilir veya `regex: false` olarak bırakabilirsiniz.

### Modül Kaynağını Tanımlama
`from` bölümünde, hangi Burp Suite modüllerinden gelen trafiklerin matcher bölümündeki koşullarla eşleşmesi durumunda işleme alınacağını belirtirsiniz.

```yaml
from:
  - Repeater
  - Scanner
  - Proxy
  - Intruder
```
Bu alan, eklentinin hangi Burp Suite modüllerinin işlemlerini izleyeceğini belirler. Bu bölümün belirlenmesi, eklentinizin etki alanını ve işleyişini doğrudan etkiler.

### İstekleri Tekrarlama
`repeat` bölümü, bir isteğin nasıl tekrarlanacağını tanımlar. İstekler Burp Suite içindeki "Repeat And Replace" özelliği ile kopyalanabilir.

```yaml
repeat:
  - raw_request: |
      GET /test_endpoint HTTP/1.1
      Host: example.com
      # Diğer HTTP başlıkları...
    service:
      protocol: http
      port: 80
      host: target.example.com
```

### Değerleri Çıkartma ve Kullanma
Çıkartma işlemi, belirli bir cevaptan veri çıkartmak için kullanılır. Bu çıkartılan veriler, daha sonra `replacer` bölümünde isteklerde kullanılmak üzere saklanabilir.

```yaml
extractor:
  - name: token_extractor
    from: response_body
    regex: '"token":\s*"(.+?)"'
```

### Değerleri Değiştirme
`replacer` bölümünde, istekleri oluştururken yerine koyacağınız değerleri tanımlarsınız. Bu değerler, extractor ile çıkartılmış ve muhafaza edilmiş bilgiler olabilir.

```yaml
replacer:
  - from: request_body
    replace_with: token_extractor
    regex: 'token_placeholder'
```

### Otomatik Session Güncelleme

Eklenti, birden çok yapılandırmayı desteklemenin yanı sıra, `continuousupdate` özelliği sayesinde otomatik session yönetimini de kolaylaştırır. Bu özellik, eklentinin, belirli bir session'ın sona ermesi durumunda otomatik olarak yeni bir session token'ı almasını ve devam eden tüm isteklerde bu yeni token'ı kullanmasını sağlar.

#### Yapılandırmada Continuous Update

`continuousupdate: true` ayarı, eklentinin sürekli güncelleme modunda çalıştığını belirtir ve genel yapılandırma ayarlarında yer alır. Bu özellik etkinleştirildiğinde, eklenti, belirli koşullar altında `repeat` alanındaki istekleri otomatik olarak tetikleyerek yeni session bilgilerini alır ve istekleri bu yeni bilgilerle günceller.

```yaml
continuousupdate: true

matchers:
  request:
    - - from: request_header
        contains:
          - "POST /test5"
          - "Host: localhost:5000"
          - "{\"token\":\""
  response:
    - - from: response_body
        contains:
         - "Session expired"
         - "Error"

replacers:
  - match: "SessionTokenPlaceholder"
    replace_with: "NEW_SESSION_TOKEN"
    scope: request_header

```

#### Otomatik Güncelleme Akışı

1. Eklenti, her istekte `matchers.request` koşullarını kontrol eder.
2. Eğer koşullar sağlanıyorsa ve daha önce başarılı bir `matchers.response` sonucu alınmışsa, eklenti mevcut isteği yeni session değeriyle günceller.
3. Eğer `matchers.response` kısmında belirtilen hatalar algılanırsa, bu durum genellikle session'ın sona erdiğini gösterir.
4. Eklenti, yeni bir session almak için `repeat` işlemlerini başlatır.
5. Yeni session alındıktan sonra, bu değer `replacers` kısmında tanımlı alanlarda kullanılarak ilgili istekler güncellenir.

Bu süreç, kullanıcı deneyimini bozmadan session'ın güncel kalmasını sağlar ve eklenti bu akışı otomatik olarak yineler. Bu sayede, session'ın expire olması durumunda kullanıcı işlemine kesintisiz devam edebilir.

### Yapılandırma Dosyasını Yükleme ve Kullanma
Yapılandırma dosyasını yazdıktan sonra, eklentinin arayüzüne gidin ve "Add" butonuna tıklayarak dosyayı seçin ve açın. Dosyayı yükledikten sonra, eklentinin arayüzünde dosyanın adının göründüğünü göreceksiniz. Yapılandırmanın etkin olabilmesi için "Reload" butonuna basmanız gerekmektedir.

### Çoklu Yapılandırmaları Destekleme
Eklenti birden fazla yapılandırma dosyasını destekler. Bu, farklı senaryolar veya testler için çeşitli yapılandırmaları tutmanıza ve ihtiyacınıza göre etkinleştirmenize olanak tanır.

# Örnek Senaryolar ve Yapılandırma Dosyaları

Eklentimiz, çeşitli kullanım senaryolarına göre önceden hazırlanmış yapılandırma dosyaları ve uygulama örnekleri ile birlikte gelir. Bu örnekler, eklentinin gücünü ve esnekliğini keşfetmenizi sağlayacak ve gerçek dünya senaryolarına nasıl uygulanacağını gösterecek şekilde tasarlanmıştır.

#### Session Yenileme Örneği

Session yönetimi için özel bir yapılandırma gerektiren durumlar, `continuousupdate` özelliği kullanılarak ele alınabilir. Örneğin, bir session'ın süresi dolarsa ve yenilenmesi gerekirse, eklenti bu işlemi otomatik olarak gerçekleştirebilir. Bu özelliği içeren ve nasıl kullanılacağını gösteren örnek bir yapılandırma dosyasını `examples/session-update` klasörü altında bulabilirsiniz.

Bu klasördeki dosyalar, session süresinin dolması durumunda otomatik olarak yenilenmesi gereken token'ların nasıl ele alınacağını açıklar. Örnek senaryo, eklentinin response matcher'ı kullanarak session'ın geçersiz olduğunu tespit ettiğinde ve bu durumda `continuousupdate` özelliği sayesinde yeni bir session token alarak işleme devam ettiğini gösterir.

#### Standart İstek Tekrarlama Örneği

Her istek yapıldığında belirli bir akışın tekrarlanmasını sağlayan standart bir senaryo için örnekler, `examples/standard-repeat` klasöründe yer almaktadır. Bu örnekler, matcher ve replacer konfigürasyonlarının nasıl kullanılacağını, bir isteğin nasıl değiştirileceğini ve isteklerin nasıl tekrar edileceğini adım adım açıklar.

Bu örneklerde, belirli bir koşul altında otomatik olarak istekleri değiştirmek veya belirli başlıkları eklemek gibi senaryolar yer almaktadır. Kullanıcılar, bu örnekleri kendi ihtiyaçlarına göre özelleştirebilir ve kendi akışlarını oluşturmak için kullanabilirler.

#### Örnekleri Kullanmak

Her iki senaryo için de örnek yapılandırma dosyaları ve kullanım senaryolarını inceleyerek eklentinin nasıl kullanılacağını öğrenebilir ve kendi durumunuz için uygulayabilirsiniz. Bu örnekleri incelemek, eklentinin işlevselliğini daha iyi anlamanızı sağlar ve sizin için en uygun olan özellikleri nasıl kullanabileceğinizi gösterir.

[examples](examples/) klasörünü ziyaret ederek eklentimizin çeşitliliğini ve kullanım kolaylığını keşfedin ve kendi kullanım durumlarınıza nasıl entegre edebileceğinizi öğrenin.
