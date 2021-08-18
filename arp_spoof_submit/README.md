# send-arp-test

과제 제출입니다.
VMware 안의 공격자 호스트에서 ICMP 패킷이 잡히지 않아 로컬에서 Wireshark로 캡쳐하였습니다.

target ip: 192.168.0.1


target mac: 70:5D:CC:E6:E2:54

you1 ip: 192.168.0.2


you1 mac: 98:2c:bc:51:0b:c6

you2 ip: 192.168.0.18


you2 mac: BE:7B:B6:8C:D0:3F

me ip: 192.168.0.27


me mac: 00:0c:29:d4:64:88

![image](https://user-images.githubusercontent.com/60030828/127908294-9c4df231-2f3d-4f6f-acad-ac7dce17cd15.png)


[사진1] - 공격자 VM(kali linux)에서 ARP Spoofing 공격 이후 로컬(windows)에서 패킷이 공격자 pc로 들어오는 화면 캡처


(192.168.0.18은 android 휴대폰에서 진행했는데, 패킷 전송 간격이 windows의 ping -t 보다 많아서 들어오는 패킷의 수가 많이 차이나며, 이유는 모르겠지만 안드로이드 폰의 arp 테이블이 기존으로 갱신되는 속도가 windows보다 빠른 것으로 보였음)

![image](https://user-images.githubusercontent.com/60030828/127908572-378fc1f6-c2cf-40b1-bb3f-d7160893b14b.png)


[사진2] - 공격자 VM에서 ARP Spoofing을 진행하고, IP를 입력값으로 받아서 YOU의 MAC주소를 받아오고 스푸핑을 성공했다는 메시지를 출력하는 모습

![image](https://user-images.githubusercontent.com/60030828/127908757-ef6d13e0-87b2-478c-ba7a-15003c8dc5e1.png)


[사진3] - 사진 2를 실행하고, 같은 환경(kali)에서 wireshark으로 arp request와 arp reply를 성공적으로 주고받은 화면.
