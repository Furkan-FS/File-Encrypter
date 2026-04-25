# RPM Encrypter - Güvenli Klasör Şifreleyici ◈

RPM Encrypter, modern kriptografik standartları kullanarak klasörlerinizi yüksek güvenlikli `.vault` dosyalarına dönüştüren, tam özellikli bir masaüstü uygulamasıdır. Kullanıcı dostu arayüzü ile verilerinizi AES-256-GCM ve Argon2id algoritmalarıyla koruma altına alır.

## 🛡️ Güvenlik Özellikleri

Bu uygulama, günümüzün en güvenilir şifreleme yöntemlerini bir araya getirir:

- **Şifreleme Algoritması:** AES-256-GCM (Galois/Counter Mode). Bu yöntem sadece şifreleme yapmakla kalmaz, aynı zamanda verinin bütünlüğünü ve orijinalliğini de doğrular (Authenticated Encryption).
- **Anahtar Türetme (KDF):** Argon2id. Brute-force ve GPU tabanlı saldırılara karşı dirençli, ödüllü anahtar türetme fonksiyonu.
- **Şifre Analizi:** `zxcvbn` kütüphanesi ile gerçek zamanlı şifre gücü ölçümü ve entropi hesabı.
- **Güvenli Silme (Secure Wipe):** Orijinal dosyaları silerken rastgele verilerle üzerine yazarak (overwriting) geri getirilmesini imkansız hale getirir.
- **Re-Key:** Vault dosyasını tamamen çözmeden şifresini değiştirebilme imkanı.

## ✨ Temel Özellikler

- **Klasör Şifreleme:** Tüm klasör yapısını tek bir şifreli `.vault` dosyasında paketler.
- **Toplu İşlem:** Birden fazla klasörü aynı anda şifreleme veya çözme.
- **Şifre Üretici:** Kriptografik olarak güvenli, yüksek entropili rastgele şifreler oluşturma.
- **Detaylı Bilgi Paneli:** Vault dosyalarının içeriğini (dosya listesi, oluşturma tarihi, sıkıştırma oranı vb.) şifre ile görebilme.
- **Görünüm Özelleştirme:** Dinamik tema desteği, renk paleti seçimi ve font boyutlarını ayarlama.

## 🚀 Kurulum

### Gereksinimler

Uygulamayı çalıştırmak için sisteminizde Python 3.8+ yüklü olmalıdır.

### Bağımlılıkların Yüklenmesi

Gerekli kütüphaneleri terminal üzerinden yükleyin:

```bash
pip install cryptography argon2-cffi zxcvbn customtkinter tkinterdnd2
```

### Çalıştırma

```bash
python secure_vault.py
```

## 📦 Uygulamayı .exe Haline Getirme

Windows üzerinde taşınabilir bir dosya oluşturmak için PyInstaller kullanabilirsiniz:

```bash
pyinstaller --noconsole --onefile --name "SecureVault" --collect-all tkinterdnd2 --collect-all customtkinter secure_vault.py
```

## 🛠️ Kullanılan Teknolojiler

- **Python:** Uygulama çekirdeği.
- **CustomTkinter:** Modern ve karanlık mod uyumlu GUI.
- **Cryptography (PyCA):** Endüstri standardı kripto işlemleri.
- **Argon2-cffi:** Güvenli parola işleme.
- **TkinterDnD2:** Sürükle-bırak entegrasyonu.

## ⚠️ Önemli Uyarı

Bu uygulama yüksek düzeyde güvenlik sağlar. Ancak:
1. **Şifrenizi Unutmayın:** Şifrenizi kaybederseniz verilerinizi kurtarmanın hiçbir yolu yoktur (Backdoor yoktur).
2. **Yedekleme:** Kritik işlemlerden (özellikle Re-Key ve Secure Wipe) önce verilerinizin yedeğini almanız önerilir.
3. **Sorumluluk:** Yazılım "olduğu gibi" sunulmaktadır; kullanım kaynaklı veri kayıplarından kullanıcı sorumludur.

---
**Geliştirici:** [RPM]
*Versiyon: 1.0*