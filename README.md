### مختبر صيد التهديدات وتحليل السجلات (Threat Hunting & Detection Lab)
هذا المستودع يوثق رحلتي في هندسة الكشف (Detection Engineering) والبحث عن التهديدات السيبرانية. من خلال هذا المختبر، قمت بمحاكاة سيناريوهات هجوم حقيقية، وتحليل السجلات (Logs)، وتطوير قواعد كشف فعالة لرصد الأنشطة المشبوهة.

### جدول مؤشرات الاختراق الرئيسي (Master IOC Table)
يُلخص هذا الجدول العمليات التحقيقية التي تم تنفيذها والإجراءات المتخذة حيالها:
### Master IOC Table

| Case | Timestamp | Source IP | Destination IP | IOC Type | Technique / Tool | Action Taken |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| #1 | 5/29/26 12:01 AM | 127.0.0.1(local) | DESKTOP-HE83QAGO | Event ID 4625 | Brute Force | Disabled Account |
| #2 | 5/31/26 21:13 PM | DESKTOP-HE83QAGO | Internal | ScriptBlock | PowerShell (Encoded) | Terminated Process |
| #3 | 5/31/26 10:57:22 PM | 192.168.88.1 | 192.168.88.138 | Domain / Query | DNS Tunneling | Isolated Host |
| #4 | 06/01/2026 18:32 | 192.168.8.237 | 192.168.88.138 | IP / Port | C2 Beaconing | Blocked C2 Traffic |

---



### أدوات وبيئة العمل (Lab Environment)
لقد قمت ببناء بيئة معملية متكاملة لمحاكاة شبكة مؤسسية حقيقية، شملت الأنظمة والأدوات التالية:


1.بيئة الأنظمة (Endpoints): 
- Windows 11 & Windows 10: تم استخدامها كأجهزة مستخدمين لتوليد سجلات الأحداث (Event Logs).
- Kali Linux: تم استخدامه كمنصة هجوم (Attacker Machine) لتنفيذ سيناريوهات الاختراق ومحاكاة الاتصالات المشبوهة.


2.تحليل الشبكة (Network Analysis):
**Zeek (Bro): لتحليل حركة المرور (Network Metadata) واستخراج مؤشرات الاختراق.**
**Wireshark: لفحص وتحليل حزم البيانات (PCAP) بشكل دقيق.**

3.الإدارة والتحليل (SIEM)
**Splunk: منصة مركزية لجمع وتحليل السجلات من جميع الأجهزة.**

* الإطار المرجعي: الاعتماد على MITRE ATT&CK لتصنيف التكتيكات والتقنيات المكتشفة.

---

### تفاصيل التحقيقات والنتائج
1/ كشف هجمات التخمين (Brute Force)
الوصف: رصد محاولات دخول غير مصرح بها عبر سجلات أحداث ويندوز (Event ID 4625).

- الاستعلام (SPL):


```
index=windows EventCode=4625
| bin _time span=5m
| stats count by IpAddress, TargetUserName, WorkstationName
| where count > 5
| sort - count

```

2/ تحليل أوامر PowerShell المشبوهة
- الوصف:مراجعة الأوامر التي تحتوي على علامات مشبوهة مثل `-EncodedCommand` أو `-bypass` التي يستخدمها المهاجمون لتنفيذ سكريبتات خفية.

 * الاستعلام (SPL):

 ```
index=windows (EventCode=4688 OR EventCode=1) 
| search CommandLine="*powershell*" AND (CommandLine="*-e*" OR CommandLine="*-enc*" OR CommandLine="*bypass*")
| table _time, ComputerName, User, CommandLine



```




3/ كشف تسريب البيانات عبر DNS
* الوصف: رصد استغلال بروتوكول DNS لنقل البيانات.

- الاستعلام (SPL):

```
index=network sourcetype=dns
| stats count by query, src_ip
| where len(query) > 50 OR count > 100
| sort - count

```


4/ رصد اتصالات التحكم والسيطرة (C2)
- الوصف:
 تحليل أنماط الاتصال الدوري (Periodicity) بين النظام المخترق وخادم C2 باستخدام سجلات Zeek.

* الاستعلام (SPL):

```
index=network sourcetype=zeek_conn
| stats count, avg(duration) as avg_duration, stdev(duration) as interval_stdev by src_ip, dest_ip
| where interval_stdev < 1 
| sort - count

```

---

### توثيق الأدلة (Evidence)
يمكنكم الاطلاع على النتائج التفصيلية لكل حالة عبر الروابط التالية:

* **Case 1:** [عرض التقرير](https://github.com/shrouqobaid/Threat-Hunting-Detection-Lab/issues/2)
* **Case 2:** [عرض التقرير](https://github.com/shrouqobaid/Threat-Hunting-Detection-Lab/issues/3)
* **Case 3:** [عرض التقرير](https://github.com/shrouqobaid/Threat-Hunting-Detection-Lab/issues/5)
* **Case 4:** [عرض التقرير](https://github.com/shrouqobaid/Threat-Hunting-Detection-Lab/issues/4)



### تقرير الربط النهائي (Case 5: Correlation & Incident Report)
هذا التقرير يمثل المرحلة النهائية لعملية ربط كافة الأدلة والمؤشرات الأمنية (IOCs) المستخرجة من الحالات السابقة:

* **Case 5:** [تحميل تقرير الحادثة (PDF)](https://github.com/shrouqobaid/Threat-Hunting-Detection-Lab/blob/main/docs/Incident_Correlation_Report.pdf)
---

### هيكلة المستودع (Repository Structure)

<div dir="ltr" align="left">
  <ul>
    <li><a href="data/">data/</a> : يحتوي على بيانات محاكاة التهديدات وملفات السكريبتات </li>
    <li><a href="docs/">docs/</a> : توثيق تفصيلي إضافي لعملية البحث عن التهديدات </li>
    <li><a href="screenshots/">screenshots/</a> : يحتوي على الأدلة البصرية لنتائج التحقيق </li>
  </ul>
</div>



---
**تم إعداد هذا المختبر لتعزيز مهارات الدفاع الاستباقي عن الشبكات.**
