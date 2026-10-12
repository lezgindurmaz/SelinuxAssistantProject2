# GuardX Antivirus

GuardX, Android için yerel C++ tarama bileşeni ve Kotlin arayüzü içeren bir antivirüs/cihaz bütünlüğü prototipidir. Aşağıdaki yetenekler proje açıklamasında listelenmiştir; her özellik bağımsız olarak doğrulanmış bir release garantisi değildir.

## Projede listelenen özellikler
- Yerel imza veritabanı ve bulut sorgusu ile tarama
- TEE/Verified Boot ve Google Play Integrity kontrolleri
- Root ve hooking tespiti
- Davranış izleme ve uygulama bütünlüğü önlemleri

## Teknik bilgiler
- Kotlin, Jetpack Compose ve C++17
- Package/application ID: `com.selinuxassistant.guardx`
- Proje ayarı `GuardX` olarak adlandırılmıştır.

## Derleme

Depoda Gradle wrapper (`gradlew`) bulunmuyor. Android Studio ile açıp Gradle senkronizasyonu yapın; terminalden derleme için uyumlu sistem Gradle’ı ile Android SDK/NDK ve CMake kurulumu gerekir:

```bash
gradle assembleDebug
```

Derleme burada çalıştırılmadı.

## Sürüm durumu

Ana daldaki Android yapılandırması `versionName 1.1.0` ve `versionCode 1` bildiriyor. Son yayımlanan release etiketi [`v1.0-alpha`](https://github.com/lezgindurmaz/SelinuxAssistantProject2/releases/tag/v1.0-alpha); bu nedenle ana daldaki 1.1.0 değeriyle aynı yayımlanmış sürüm olarak varsayılmamalıdır. Yeni release oluşturulmadı ve build sürüm numaraları değiştirilmedi.

## Uyarı

Bu proje eğitim ve güvenlik araştırması amacıyla tanımlanmıştır. Release dosyaları ve notları [GitHub Releases](https://github.com/lezgindurmaz/SelinuxAssistantProject2/releases) bölümündedir.
