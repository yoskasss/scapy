from scapy.all import *  # Scapy kütüphanesindeki tüm fonksiyonları içe aktar

eth = Ether()  # Ethernet çerçevesi (frame) oluştur
arp = ARP()    # ARP (Address Resolution Protocol) paketi oluştur

eth.dst = "ff:ff:ff:ff:ff:ff"  # Ethernet çerçevesinin hedef adresini "ff:ff:ff:ff:ff:ff" (broadcast) olarak ayarla
arp.pdst = "192.168.32.1/24"     # ARP paketinde hedef IP adresini "10.10.10.1/24" ağı olarak ayarla

bcPckt = eth / arp  # Ethernet ve ARP katmanlarını birleştirerek bir yayın (broadcast) paketi oluştur

#bcPckt.show()  # Paketin içeriğini detaylı olarak göster (yorum satırına alınmış)

# srp fonksiyonunu kullanarak yayın paketini gönder ve cevapları al (timeout: 5 saniye)
ans, unans = srp(bcPckt, timeout=5)

#ans.summary()  # Alınan cevapların özetini yazdır (yorum satırına alınmış)
print("#" * 30)  # Ekranda ayrım yapmak için 30 adet # karakteri yazdır
#unans.summary()  # Cevap alınamayan (yanıtsız) paketlerin özetini yazdır (yorum satırına alınmış)

# Gelen cevapları döngü ile işle
for snd, rcv in ans:
    #rcv.show()  # Alınan cevabın içeriğini detaylı olarak göster (yorum satırına alınmış)
    print(rcv.psrc, " : ", rcv.src)  # Cevap veren cihazın IP adresini (rcv.psrc) ve MAC adresini (rcv.src) yazdır
