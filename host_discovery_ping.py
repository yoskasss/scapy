from scapy.all import IP, ICMP, sr1  # Scapy kütüphanesinden IP, ICMP ve sr1 fonksiyonlarını içe aktar

ip = IP()  # IP protokolü için bir nesne oluştur
icmp = ICMP()  # ICMP protokolü için bir nesne oluştur
pingPckt = ip / icmp  # IP ve ICMP katmanlarını birleştirerek bir ping paketi oluştur

addr = "10.10.10."  # Ping atılacak IP adreslerinin başlangıç kısmını tanımla

for i in range(0,130):  # 0'dan 129'a kadar olan adres aralığını döngüyle taramak için
    pingPckt[IP].dst = addr + str(i)  # Adresin son kısmına `i` değerini ekle, örn: 10.10.10.0, 10.10.10.1, ...
    
    # Ping paketini gönder ve yanıt bekle, timeout süresi 0.5 saniye, ve çıktıyı gizle (verbose=False)
    response = sr1(pingPckt, timeout=0.5, verbose=False)  
    
    # Eğer bir yanıt gelirse
    if response:
        print(pingPckt[IP].dst, "is up")  # IP adresinin aktif olduğunu belirt
    else:
        pass  # Yanıt gelmezse hiçbir şey yapma (adres kapalı veya yanıt vermiyor)
